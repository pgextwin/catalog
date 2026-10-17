#!/usr/bin/env python3
"""Issue #112 source v2: independently sealed append-only 40-row admission.

A formal source ledger is NOT a P1 admission or permission to distribute.
Optional --audit-zip validates exact protected-main original audit bytes.
Offline fixture tests do not establish original cryptographic provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile
import zlib

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_historical_fleet import blob_sha, pins_load
from distribution_p1_historical_source import (
    INVENTORY, INVENTORY_GIT_BLOB, LEDGER as GENESIS,
    LEDGER_GIT_BLOB as GENESIS_BLOB, IDENTITY, TARGETS, MAJORS,
    load_inventory, source_receipt, source_summary, validate_formal_v1)
from distribution_p1_formal_ledger_v4 import PINS, FLEET

ROOT = Path(__file__).resolve().parents[1]
V2 = ROOT / "evidence/source/formal-historical-source-v2.json"
V2_GIT_BLOB = "7853e671c9ea8a06f7d477cbec63c285e76b5be6"
AUDIT_RUN_ID = 38996155344
AUDIT_COMMIT = "b6811db3a6566d98d89deb277d63cea9cd1653e8"
AUDIT_ARTIFACT_ID = 12087103198
AUDIT_ZIP_SHA256 = "3c7c6a478aa3019c93af958f2eee19a797d575ad7da2c86e3858ea2ffcdb136f"
LEDGER_KEYS = {"extension", "pgMajor", "repositoryId", "releaseId", "assetId",
               "assetName", "originalZipSha256", "originalRunId",
               "originalRunAttempt", "originalBuildJobId", "originalPublishJobId",
               "sourceReceiptSha256"}
SAFE_GATE = {"p1FormalAccepted":65, "p1FormalTotal":70, "p1":"BLOCKED",
             "p2":"NO-GO", "publicationAuthorized":False,
             "distributionAuthorized":False, "formalDistribution":"DENY"}

def validate_ledger(raw: bytes, *, inventory_raw: bytes | None = None,
                    genesis_raw: bytes | None = None) -> tuple[dict, dict]:
    """Validation of immutable accepted ledger and its unmodified v1 ancestor."""
    require(blob_sha(raw) == V2_GIT_BLOB, "v2 source ledger raw Git Blob unsealed")
    genesis = validate_formal_v1(genesis_raw if genesis_raw is not None
                                 else GENESIS.read_bytes())
    fleet = strict_json(FLEET.read_bytes())
    pins = pins_load(PINS.read_bytes(), fleet)
    identities = load_inventory(inventory_raw if inventory_raw is not None
                                else INVENTORY.read_bytes(), pins, fleet)
    data = strict_json(raw)
    require(type(data) is dict and set(data) == {
        "schema", "previousLedgerGitBlob", "previousSourceFormalAccepted",
        "inventoryGitBlob", "previousP1LedgerGitBlob", "sourceAudit",
        "acceptedRows", "sourceFormalAccepted", "sourceFormalTotal",
        "p1FormalAccepted", "p1FormalTotal", "p1", "p2",
        "publicationAuthorized", "distributionAuthorized",
        "formalDistribution", "note"}, "v2 unexpected schema")
    require(data["schema"] == "pgextwin-historical-source-formal-acceptance/v2"
            and data["previousLedgerGitBlob"] == GENESIS_BLOB
            and data["previousSourceFormalAccepted"] == genesis["sourceFormalAccepted"] == 0
            and data["inventoryGitBlob"] == INVENTORY_GIT_BLOB
            and data["previousP1LedgerGitBlob"] == genesis["previousP1LedgerGitBlob"],
            "v2 predecessor/immutable inventory chain invalid")
    audit = data["sourceAudit"]
    require(type(audit) is dict and audit == {
        "repository": "pgextwin/catalog", "runId": AUDIT_RUN_ID,
        "runCommit": AUDIT_COMMIT, "artifactId": AUDIT_ARTIFACT_ID,
        "artifactZipSha256": AUDIT_ZIP_SHA256, "artifactFileCount": 126,
        "sourceCandidateCount": 40, "artifactRunConclusion": "failure",
        "originalReleaseReceipts": 14, "originalP1Denials": 5},
        "v2 real protected-main original audit identity changed")
    require(all(type(data[k]) is type(v) and data[k] == v
                for k, v in SAFE_GATE.items()) and
            type(data["sourceFormalAccepted"]) is int and
            data["sourceFormalAccepted"] == 40 and
            type(data["sourceFormalTotal"]) is int and
            data["sourceFormalTotal"] == 40 and
            type(data["note"]) is str and data["note"].startswith("40 source rows"),
            "formal source count or invariant P1/distribution DENY altered")
    rows = data["acceptedRows"]
    require(type(rows) is list and len(rows) == 40, "source admission has incomplete rows")
    admitted = {}
    for row in rows:
        require(type(row) is dict and set(row) == LEDGER_KEYS,
                "source v2 row missing/extra identity fields")
        key = (row["extension"], row["pgMajor"])
        require(key in identities and key not in admitted,
                "duplicate/wrong PG or extension in v2 admission")
        pinned = identities[key]
        for field in LEDGER_KEYS - {"sourceReceiptSha256"}:
            require(type(row[field]) is type(pinned[field]) and
                    row[field] == pinned[field], "v2 admission original identity substitution")
        sha = row["sourceReceiptSha256"]
        require(type(sha) is str and len(sha) == 64 and
                all(c in "0123456789abcdef" for c in sha),
                "source receipt lacks exact 64-digit digest")
        admitted[key] = row
    require(set(admitted) == set(identities) and
            len({r["sourceReceiptSha256"] for r in rows}) == 40,
            "40 distinct receipt digests and full source matrix required")
    return data, identities

def validate_artifact(zip_bytes: bytes, ledger_raw: bytes | None = None) -> dict:
    """Accept only byte-identical protected-main audit and recompute 40 source receipts."""
    ledger, identities = validate_ledger(ledger_raw if ledger_raw is not None
                                         else V2.read_bytes())
    require(type(zip_bytes) is bytes and
            hashlib.sha256(zip_bytes).hexdigest() == AUDIT_ZIP_SHA256,
            "protected-main original audit ZIP SHA256 mismatch")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        names = archive.namelist()
        expected = {f"{n}-pg{pg}.json" for n in
                    ("hypopg", "orafce", "pg_partman", "pg_stat_monitor",
                     *TARGETS, "plpgsql_check", "wal2json")
                    for pg in MAJORS}
        expected |= {f"{n}-release.json" for n in
                     ("hypopg", "orafce", "pg_partman", "pg_stat_monitor",
                     *TARGETS, "plpgsql_check", "wal2json")}
        expected |= {f"{n}-pg{pg}-source.json" for n in TARGETS for pg in MAJORS}
        expected |= {"summary.json", "source-summary.json"}
        require(len(names) == 126 and len(set(names)) == 126 and set(names) == expected,
                "audit files missing, duplicated or unexpectedly added")
        require(all(info.CRC == ( zlib.crc32(archive.read(info)) & 0xffffffff)
                    for info in archive.infolist()),
                "audit ZIP CRC mismatch")
        def read_obj(name):
            return strict_json(archive.read(name))
        p1summary = read_obj("summary.json")
        ssummary = read_obj("source-summary.json")
        require(p1summary["formalP1Accepted"] == 65
                and p1summary["formalP1Total"] == 70
                and p1summary["batchDecisions"] == {
                    "ALREADY_ACCEPTED":6, "PASS_CANDIDATE":59,
                    "DENY":5, "BLOCKED":0}
                and p1summary["publicationAuthorized"] is False
                and p1summary["distributionAuthorized"] is False
                and p1summary["fleetComplete"] is False
                and ssummary["sourceCandidatesNotYetFormallyAdmitted"] == 40
                and ssummary["sourceBlocked"] == 0
                and ssummary["sourceFormalAccepted"] == 0
                and ssummary["p1FormalAccepted"] == 65
                and ssummary["publicationAuthorized"] is False
                and ssummary["distributionAuthorized"] is False,
                "protected-main raw audit summaries contradict independent v2 admission")
        by_key = {(r["extension"], r["pgMajor"]):r for r in ledger["acceptedRows"]}
        fleet = strict_json(FLEET.read_bytes())
        for key, identity in identities.items():
            n, pg = key
            name = f"{n}-pg{pg}-source.json"
            original = archive.read(name)
            row = by_key[key]
            require(hashlib.sha256(original).hexdigest() == row["sourceReceiptSha256"],
                    "sealed source receipt does not match actual original run bytes")
            observed = strict_json(original)
            p1 = read_obj(f"{n}-pg{pg}.json")
            if key == ("pg_bigm", 14):
                require(p1["decision"] == "ALREADY_ACCEPTED" and
                        p1["formalAcceptedByThisRun"] is False and
                        type(p1.get("sourceOnlyGenuineP1")) is dict,
                        "PG14 original exception must have separate genuine source rerun")
                p1 = p1["sourceOnlyGenuineP1"]
                require(p1["signatureProof"].get("sourceOnlySeparatePG14Rerun") is True,
                        "PG14 original source separately rechecked proof missing")
            release = read_obj(f"{n}-release.json")
            recalculated = source_receipt(identity, release, p1,
                official_gh_sha=fleet["officialGhSha256"][0],
                trusted_root_sha=fleet["rootSha256"])
            require(recalculated == observed and
                    recalculated["decision"] == "SOURCE_PASS_CANDIDATE" and
                    recalculated["formalSourceAccepted"] is False and
                    recalculated["publicationAuthorized"] is False and
                    recalculated["distributionAuthorized"] is False,
                    "archived candidate source receipt not corroborated by genuine same-run P1/Release")
            for k, v in row.items():
                if k in ("sourceReceiptSha256",):
                    continue
                require(observed[k] == v, "archived source receipt identity and ledger differ")
        return {"sourceFormalAccepted": 40, "sourceFormalTotal": 40,
                "sourceCandidateReceiptsRechecked": 40,
                "archiveSha256Verified": True, "p1FormalAccepted": 65,
                "publicationAuthorized": False, "distributionAuthorized": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-zip", type=Path,
                        help="Explicit original Actions Artifact ZIP (never download in this script)")
    args = parser.parse_args()
    if args.audit_zip:
        result = validate_artifact(args.audit_zip.read_bytes())
    else:
        result, _ = validate_ledger(V2.read_bytes())
        result = {"sourceFormalAccepted":result["sourceFormalAccepted"],
                  "archivedBytesRecheckedNow":False,
                  "note":"Sealed admission ledger only; supply --audit-zip to recompute original receipt binding"}
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
