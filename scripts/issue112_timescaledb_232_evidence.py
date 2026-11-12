#!/usr/bin/env python3
"""Strict offline join of exact authenticated 2.32.0 original CI receipts. Never authorizes GET."""
import json
from pathlib import Path

from external_new_stable_watch import unique_json_pairs

EVIDENCE_PATH = "external/timescaledb-232-original-evidence-v1.json"
RUN_SHA = "84f6aa357a4b7dcbc33af4db72986b29a9530de9"
RUN_ID = 43242594902
# Immutable job identities and independently observed ZIP inventory from original push logs.
JOBS = {
    "16": (131266732291, 78, 3, 33752961),
    "17": (131266732923, 78, 3, 33754497),
    "18": (131266732862, 78, 3, 33756545),
}


def verified_assets(root, baseline):
    path = Path(root) / EVIDENCE_PATH
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 20000:
        raise ValueError("Missing or unbounded exact TimescaleDB original evidence")
    receipt = json.loads(path.read_text(encoding="utf-8"),
                         object_pairs_hook=unique_json_pairs)
    if type(receipt) is not dict or set(receipt) != {
            "schemaVersion", "scope", "sourceRepo", "releaseTag", "releaseId",
            "originalRehashRun", "assets", "verification", "permissions"}:
        raise ValueError("Unexpected independent original evidence fields")
    if (receipt["schemaVersion"] !=
            "pgextwin-issue112-timescaledb-232-independent-original-evidence/v1"
            or receipt["scope"] != "CANDIDATE_ONLY_NONPUBLISHING"
            or receipt["sourceRepo"] != "timescale/timescaledb"
            or receipt["releaseTag"] != "2.32.0"
            or type(receipt["releaseId"]) is not int
            or receipt["releaseId"] != 442824242):
        raise ValueError("Wrong evidence identity or publishing state")
    run = receipt["originalRehashRun"]
    if type(run) is not dict or run != {
            "repository": "pgextwin/catalog", "runId": RUN_ID, "event": "push",
            "attempt": 1, "headSha": RUN_SHA,
            "workflowPath": ".github/workflows/issue112-timescaledb-232-original-rehash.yml",
            "conclusion": "success",
            "trust": "GITHUB_AUTHENTICATED_RUN_AND_JOBS_GET_NOT_SIGNED_PROVENANCE"}:
        raise ValueError("Unreviewed or replayed original run identity")
    if receipt["verification"] != {
            "actualResponseSha256AndLength": True, "zipPathCrcAndBounds": True,
            "windowsRuntime": False, "rightsNoticeDependencyClosure": False,
            "producerSignedSourceToZipProvenance": False,
            "independentSignedAdmission": False}:
        raise ValueError("Receipt attempts to promote unverified acceptance")
    if receipt["permissions"] != {
            "publicGet": False, "mirror": False, "redistribution": False,
            "release": False, "publisher": False}:
        raise ValueError("Receipt attempts to authorize delivery")
    if (type(baseline) is not dict or
            baseline.get("releaseTag") != "2.32.0" or
            baseline.get("releaseId") != 442824242 or
            type(baseline.get("records")) is not list or
            len(baseline["records"]) != 3):
        raise ValueError("Unreviewed official Release baseline")
    api = {r["pgMajor"]: r for r in baseline["records"]}
    if (set(api) != set(JOBS) or type(receipt["assets"]) is not list
            or len(receipt["assets"]) != len(JOBS)):
        raise ValueError("Exact PG-major original matrix required")
    joined = {}
    for row in receipt["assets"]:
        if type(row) is not dict or set(row) != {
                "pgMajor", "assetId", "assetName", "originalBytes",
                "originalSha256", "jobId", "zipInventory"}:
            raise ValueError("Unknown original ZIP receipt fields")
        pg = row["pgMajor"]
        if type(pg) is not str or pg not in JOBS or pg in joined:
            raise ValueError("Missing, duplicate or unsupported PG evidence")
        observed = api[pg]
        job_id, members, dlls, size = JOBS[pg]
        if (type(row["assetId"]) is not int or
                row["assetId"] != observed["assetId"] or
                row["assetName"] != observed["assetName"] or
                type(row["originalBytes"]) is not int or
                row["originalBytes"] != observed["apiBytes"] or
                type(row["originalSha256"]) is not str or
                row["originalSha256"] != observed["apiSha256"] or
                type(row["jobId"]) is not int or row["jobId"] != job_id):
            raise ValueError("Original evidence not bound to exact asset and CI job")
        if type(row["zipInventory"]) is not dict or row["zipInventory"] != {
                "members": members, "dllMembers": dlls,
                "declaredUncompressedBytes": size, "potentialNoticePaths": []}:
            raise ValueError("Exact original ZIP inventory mismatch")
        joined[pg] = row
    if set(joined) != set(JOBS):
        raise ValueError("Incomplete independent original receipt set")
    return joined
