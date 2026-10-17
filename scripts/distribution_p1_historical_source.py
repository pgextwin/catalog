#!/usr/bin/env python3
"""Issue #112: read-only independent historical source evidence (not P1 admission).

Called only by the original-byte protected-main batch, AFTER genuine gh/TUF
dual-Sigstore per PG verifier returned. A receipt never verifies itself.
No file in this module can authorize publication or increment P1.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_historical_fleet import blob_sha, LOG_BLOBS
from distribution_p1_formal_ledger_v5 import V5, V5_GIT_BLOB, validate as validate_p1_v5
from distribution_p1_formal_ledger_v4 import V4, PINS, FLEET

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "config/issue112-historical-source-original-40-v1.json"
INVENTORY_GIT_BLOB = "db528c079135ebfb653d844f5683672f0730a8f4"
LEDGER = ROOT / "evidence/source/formal-historical-source-v1.json"
TARGETS = ("pg_bigm", "pg_cron", "pg_hint_plan", "pg_ivm",
           "pg_qualstats", "pg_repack", "pgaudit", "set_user")
MAJORS = (14, 15, 16, 17, 18)
H40 = re.compile(r"[0-9a-f]{40}\Z")
H64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY = ("extension", "pgMajor", "repositoryId", "releaseId", "assetId",
            "assetName", "originalZipSha256", "originalZipSize",
            "packagingSha", "workflowGitBlob", "configGitBlob",
            "upstreamRepository", "upstreamRef", "upstreamVersion",
            "originalRunId", "originalRunAttempt", "originalBuildJobId",
            "originalPublishJobId", "signerSha", "sourceRef")

def load_inventory(raw: bytes, source_pins: dict, fleet: dict):
    require(blob_sha(raw) == INVENTORY_GIT_BLOB, "unsealed historical 40-row inventory")
    d = strict_json(raw)
    require(type(d) is dict and
            set(d) == {"schema", "snapshotCatalogCommit", "sourcePinsGitBlob",
                       "fleetPinsGitBlob", "source", "integrityStatus", "rows"} and
            d["schema"] == "pgextwin-historical-source-original-identity/v1" and
            d["snapshotCatalogCommit"] == fleet["catalogCommitSha"] and
            d["sourcePinsGitBlob"] == "c04a8c34688265cfd598fe99c399aa032321ed61" and
            d["fleetPinsGitBlob"] == "8b07e941ab90b2a097246c125e2eb905db7f2dea" and
            d["integrityStatus"] == "METADATA_PINS_ONLY_NOT_SIGNED_SOURCE_ACCEPTANCE",
            "historical inventory provenance/schema changed")
    rows = d["rows"]
    require(type(rows) is list and len(rows) == 40, "historical 40 rows missing")
    expected = {(n, pg) for n in TARGETS for pg in MAJORS}
    result = {}
    for row in rows:
        require(type(row) is dict and set(row) == set(IDENTITY),
                "unexpected source row keys")
        n, pg = row["extension"], row["pgMajor"]
        require(n in TARGETS and type(pg) is int and pg in MAJORS and
                (n, pg) not in result, "duplicate, wrong PG or unsupported source row")
        pin = source_pins[n]
        require(row["repositoryId"] == pin["repositoryId"] == fleet["repoIds"][n]
                and row["releaseId"] == pin["releaseId"] == fleet["releaseIds"][n]
                and row["packagingSha"] == pin["packagingSha"]
                and row["workflowGitBlob"] == pin["workflowBlob"]
                and row["configGitBlob"] == pin["configBlob"]
                and row["originalRunId"] == pin["runId"]
                and row["originalRunAttempt"] == pin["runAttempt"]
                and row["originalBuildJobId"] == pin["pgBuildJobIds"][str(pg)]
                and row["originalPublishJobId"] == pin["publishJobId"]
                and row["signerSha"] == pin["signerSha"]
                and row["sourceRef"] == pin["sourceRef"]
                and fleet["assetIds"][n].get(row["assetName"]) == row["assetId"],
                "historical source identity disagrees with two external pin registries")
        require(type(row["assetName"]) is str and
                row["assetName"].endswith(f"-pg{pg}-windows-x64.zip") and
                type(row["originalZipSha256"]) is str and
                H64.fullmatch(row["originalZipSha256"]) and
                type(row["originalZipSize"]) is int and row["originalZipSize"] > 0 and
                all(type(row[k]) is str and H40.fullmatch(row[k]) for k in
                    ("packagingSha", "workflowGitBlob", "configGitBlob", "signerSha")) and
                type(row["upstreamRepository"]) is str and "/" in row["upstreamRepository"] and
                type(row["upstreamRef"]) is str and row["upstreamRef"] and
                type(row["upstreamVersion"]) is str and row["upstreamVersion"],
                "invalid original ZIP/SHA/immutable source identity")
        result[(n, pg)] = row
    require(set(result) == expected, "incomplete exact source matrix")
    return result

def source_receipt(identity: dict, release: dict | None, p1: dict | None,
                   *, official_gh_sha: str, trusted_root_sha: str) -> dict:
    """Use evidence only from the SAME genuine original-Release crypto execution.

    This is a candidate source observation, NEVER formal acceptance.
    Source proof is separately classified even when P1 was formally accepted.
    """
    n, pg = identity["extension"], identity["pgMajor"]
    out = {"schema": "pgextwin-historical-source-row/v1", **identity,
           "decision": "BLOCKED", "reason": "", "upstreamCommit": None,
           "originalCheckoutLogSha256": None, "bundleSha256": None,
           "p1RowReceiptSha256": None, "publicationAuthorized": False,
           "distributionAuthorized": False, "formalSourceAccepted": False}
    def verify():
        require(type(release) is dict and type(p1) is dict, "BLOCKED: genuine release/PG inspection missing")
        require(release.get("type") == "release" and
                release.get("extension") == n and
                release.get("repositoryId") == identity["repositoryId"] and
                release.get("releaseId") == identity["releaseId"] and
                release.get("allAssetsRehashed") is True and
                release.get("allPgZipCrcVerified") is True and
                release.get("allPgSpdxGrypeStructured") is True and
                release.get("assetIds", {}).get(identity["assetName"]) == identity["assetId"] and
                release.get("assetSha256", {}).get(identity["assetName"]) == identity["originalZipSha256"],
                "BLOCKED: original Release real bytes/digest/ID not independently corroborated")
        require(p1.get("type") == "row" and p1.get("extension") == n and
                p1.get("pgMajor") == pg and
                p1.get("repositoryId") == identity["repositoryId"] and
                p1.get("releaseId") == identity["releaseId"] and
                p1.get("assetId") == identity["assetId"] and
                p1.get("packagingSha") == identity["packagingSha"] and
                p1.get("decision") == "PASS_CANDIDATE" and
                p1.get("verificationOrigin") == "genuine" and
                p1.get("verificationProfile") == "historical/windows.yml/push/v1" and
                p1.get("signatureVerified") is True and
                p1.get("integrityVerified") is True and
                p1.get("runId") == identity["originalRunId"] and
                p1.get("runAttempt") == identity["originalRunAttempt"] and
                p1.get("officialGhSha256") == official_gh_sha and
                p1.get("trustedRootSha256") == trusted_root_sha and
                H64.fullmatch(official_gh_sha) and H64.fullmatch(trusted_root_sha),
                "BLOCKED: genuine signed original per-PG P1 cryptography not established")
        proof = p1.get("signatureProof")
        require(type(proof) is dict and
                proof.get("buildJobId") == identity["originalBuildJobId"] and
                proof.get("publicationJobId") == identity["originalPublishJobId"] and
                proof.get("originalCheckoutJobId") == identity["originalBuildJobId"] and
                proof.get("originalCheckoutRunAttempt") == identity["originalRunAttempt"] and
                proof.get("originalCheckoutArchiveBlob") == LOG_BLOBS[n] and
                proof.get("workflowBlob") == identity["workflowGitBlob"] and
                proof.get("configBlob") == identity["configGitBlob"] and
                proof.get("signerSha") == identity["signerSha"] and
                proof.get("upstreamRepository") == identity["upstreamRepository"] and
                proof.get("upstreamRef") == identity["upstreamRef"] and
                type(proof.get("upstreamCommit")) is str and
                H40.fullmatch(proof["upstreamCommit"]) and
                type(proof.get("originalCheckoutLogSha256")) is str and
                H64.fullmatch(proof["originalCheckoutLogSha256"]) and
                type(proof.get("bundleSha256")) is str and
                H64.fullmatch(proof["bundleSha256"]) and
                ((n,pg) != ("pg_bigm",14) or
                 proof.get("sourceOnlySeparatePG14Rerun") is True),
                "BLOCKED: historical upstream full SHA, immutable log, original PG14 recheck or signed subject evidence missing")
        return proof
    try:
        proof = verify()
        out.update(decision="SOURCE_PASS_CANDIDATE", reason="genuine original bytes, dual Sigstore, immutable original PG checkout and upstream proof",
                   upstreamCommit=proof["upstreamCommit"],
                   originalCheckoutLogSha256=proof["originalCheckoutLogSha256"],
                   bundleSha256=proof["bundleSha256"])
        # Hash original same-run P1 receipt. It does not authenticate itself.
        raw = (json.dumps(p1, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        out["p1RowReceiptSha256"] = hashlib.sha256(raw).hexdigest()
    except (Denied, KeyError, ValueError, TypeError, AttributeError) as exc:
        out["reason"] = str(exc)[:240]
    return out

def source_summary(rows: list) -> dict:
    require(type(rows) is list and len(rows) == 40 and
            len({(r["extension"], r["pgMajor"]) for r in rows}) == 40,
            "missing/duplicated 40 source observations")
    counts = {n: sum(x["decision"] == n for x in rows)
              for n in ("SOURCE_PASS_CANDIDATE", "BLOCKED")}
    require(sum(counts.values()) == 40 and all(
        r["publicationAuthorized"] is False and
        r["distributionAuthorized"] is False and
        r["formalSourceAccepted"] is False for r in rows),
        "source receipt accidentally authorizes distribution/formal admission")
    return {"schema": "pgextwin-historical-source-observation/v1",
            "sourceCandidatesNotYetFormallyAdmitted": counts["SOURCE_PASS_CANDIDATE"],
            "sourceBlocked": counts["BLOCKED"],
            "sourceFormalAccepted": 0, "sourceFormalTotal": 40,
            "p1FormalAccepted": 65, "p1FormalTotal": 70,
            "p1": "BLOCKED", "p2": "NO-GO",
            "publicationAuthorized": False, "distributionAuthorized": False,
            "formalDistribution": "DENY",
            "note": "Read-only candidates require independent exact-byte receipt review, separate append-only formal ledger and protected-main real audit; NEVER auto-promote."}

def validate_formal_v1(raw: bytes) -> dict:
    """Sealed independent ZERO baseline; v2+ must prove real rows individually."""
    # Cannot derive acceptance from a self-reported source receipt or P1 v5.
    validate_p1_v5(V5.read_bytes(), V4.read_bytes(), PINS.read_bytes(), FLEET.read_bytes())
    d = strict_json(raw)
    expected = {
        "schema": "pgextwin-historical-source-formal-acceptance/v1",
        "previousP1LedgerGitBlob": V5_GIT_BLOB,
        "inventoryGitBlob": INVENTORY_GIT_BLOB,
        "acceptedRows": [], "sourceFormalAccepted": 0, "sourceFormalTotal": 40,
        "p1FormalAccepted": 65, "p1FormalTotal": 70,
        "p1": "BLOCKED", "p2": "NO-GO",
        "publicationAuthorized": False, "distributionAuthorized": False,
        "formalDistribution": "DENY"}
    require(type(d) is dict and set(d) == set(expected) and
            all(type(d[k]) is type(v) and d[k] == v for k,v in expected.items()),
            "independent source formal v1 ledger cannot self-admit or weaken gates")
    return d
