#!/usr/bin/env python3
"""Validate public Catalog's immutable original-provider GET-only signed pin archives.

This is NOT the legacy deny-only external publisher policy. The sole
source-specific admission is the genuine Build/main issuer's signed, six-hour
manifest, and every copy must have its exact Sigstore bundle. Expired entries
remain readable audit records but are NEVER active download permissions.
No original provider ZIP is stored, rehosted, or released.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_REL = Path("external/signed-direct-get/pg_trickle")
SCHEMA = "pgextwin-external-direct-get-admission/v1"
OP = "ORIGINAL_PROVIDER_GET_ONLY"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
RUN_DIR = re.compile(r"run-([1-9][0-9]{0,14})\Z")
FILES = {"external-get-admission.json", "attestation.json"}
LATEST_NAME = "latest.json"
LATEST_SCHEMA = "pgextwin-external-latest-original-pins/v1"
LATEST_KEYS = {"schemaVersion", "issuerRunId", "admissionSha256", "records"}
LATEST_ROW_KEYS = {
    "extension", "pgMajor", "sourceRepo", "repositoryId", "releaseTag",
    "releaseId", "assetName", "assetId", "originalBytes",
    "originalSha256", "originalProviderUrl",
}
KEYS = {
    "schemaVersion", "sourceKind", "issuerRepository", "issuerCommit",
    "catalogCommit", "issuerEvent", "issuerRunId", "issuerRunAttempt",
    "ownerActor", "ownerId", "publisherEnvironment", "publisherAppId",
    "approvedOperation", "issuedAt", "expiresAt", "downloadAuthorized",
    "mirrorAuthorized", "redistributionAuthorized", "records",
}
ROW_KEYS = {
    "sourceGroup", "extension", "pgMajor", "targetEnvironment", "sourceRepo",
    "repositoryId", "releaseTag", "releaseId", "assetName", "assetId",
    "originalBytes", "originalSha256", "originalProviderUrl",
    "licenseUrl", "noticeTreatment", "dependencyTreatment",
    "approvedOperation", "downloadAuthorized", "mirrorAuthorized",
}

class Denied(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Denied("signed external Catalog GET-only pin DENY: " + why)

def unique(items):
    doc = {}
    for key, value in items:
        require(key not in doc, "duplicate JSON key")
        doc[key] = value
    return doc

def parse_utc(s):
    require(type(s) is str and re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", s) is not None, "invalid UTC timestamp")
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise Denied("invalid UTC date") from None

def validate_document(doc, dirname, *, now, source="pg_trickle"):
    require(type(doc) is dict and set(doc) == KEYS, "untrusted manifest schema")
    match = RUN_DIR.fullmatch(dirname)
    require(match is not None and type(doc["issuerRunId"]) is int
            and doc["issuerRunId"] == int(match.group(1)), "manifest does not belong to directory")
    for key, val in (
        ("schemaVersion", SCHEMA), ("sourceKind", "EXTERNAL_GITHUB_RELEASE_ASSET"),
        ("issuerRepository", "pgextwin/build"),
        ("issuerEvent", "workflow_dispatch"), ("issuerRunAttempt", 1),
        ("ownerActor", "ShutenOishi"), ("ownerId", 27071164),
        ("publisherEnvironment", "external-direct-provider-publisher"),
        ("publisherAppId", 5609317), ("approvedOperation", OP),
        ("downloadAuthorized", True), ("mirrorAuthorized", False),
        ("redistributionAuthorized", False),
    ):
        require(type(doc[key]) is type(val) and doc[key] == val,
                "unauthorized elevation/identity: " + key)
    require(all(type(doc[key]) is str and SHA40.fullmatch(doc[key])
                for key in ("issuerCommit", "catalogCommit")), "invalid signed source SHA")
    issued = parse_utc(doc["issuedAt"])
    expiry = parse_utc(doc["expiresAt"])
    require(expiry - issued == timedelta(hours=6), "forged admission lifetime")
    require(issued <= now + timedelta(minutes=5), "manifest signed in the future")
    rows = doc["records"]
    if source == "hypopg":
        validate_hypopg_records(rows)
        return "ACTIVE" if issued <= now < expiry else "EXPIRED_ARCHIVE_DOWNLOAD_DENY"
    if source == "portalcorp_pgvector":
        validate_portalcorp_records(rows)
        return "ACTIVE" if issued <= now < expiry else "EXPIRED_ARCHIVE_DOWNLOAD_DENY"
    if source == "qualified_cohort":
        # Accept archived five and newly owner-signed seven exact originals.
        # Neither an archive nor offline parsing grants current authority.
        require(type(rows) is list and len(rows) in (5, 7),
                "unknown mixed-source signed cohort size")
        validate_pg_trickle_records(rows[:1])
        validate_hypopg_records(rows[1:4])
        validate_portalcorp_records(rows[4:5])
        if len(rows) == 7:
            validate_reviewed_pg18_records(rows[5:])
        return "ACTIVE" if issued <= now < expiry else "EXPIRED_ARCHIVE_DOWNLOAD_DENY"
    require(source == "pg_trickle", "unknown original source")
    validate_pg_trickle_records(rows)
    return "ACTIVE" if issued <= now < expiry else "EXPIRED_ARCHIVE_DOWNLOAD_DENY"


def validate_pg_trickle_records(rows):
    require(type(rows) is list and len(rows) == 1
            and type(rows[0]) is dict and set(rows[0]) == ROW_KEYS, "untrusted record list")
    row = rows[0]
    for key, val in (
        ("sourceGroup", "external"), ("extension", "pg_trickle"),
        ("pgMajor", "18"), ("sourceRepo", "trickle-labs/pg-trickle"),
        ("repositoryId", 1164857056), ("releaseTag", "v0.108.3"),
        ("releaseId", 404988260), ("assetId", 616203967),
        ("assetName", "pg_trickle-0.108.3-pg18-windows-amd64.zip"),
        ("originalBytes", 7029107),
        ("originalSha256", "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b"),
        ("approvedOperation", OP), ("downloadAuthorized", True), ("mirrorAuthorized", False),
        ("originalProviderUrl", "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/pg_trickle-0.108.3-pg18-windows-amd64.zip"),
        ("licenseUrl", "https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE"),
    ):
        require(type(row[key]) is type(val) and row[key] == val, "unapproved source: " + key)
    require(all(type(row[k]) is str and len(row[k]) >= 30 for k in (
        "targetEnvironment", "noticeTreatment", "dependencyTreatment")),
        "missing required end-user notice/dependencies")


def validate_hypopg_records(rows):
    """Exactly three owner-signed original ZIPs, never a generic discovery feed."""
    pins = {
        "14": (164673161, 23115,
               "ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634"),
        "15": (164673166, 23123,
               "d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec"),
        "16": (164673171, 22997,
               "7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7"),
    }
    require(type(rows) is list and len(rows) == 3, "unexpected owner-signed HypoPG cohort length")
    for pg, row in zip(("14", "15", "16"), rows):
        require(type(row) is dict and set(row) == ROW_KEYS,
                "unexpected original HypoPG record keys")
        aid, size, sha = pins[pg]
        name = f"hypopg-1.4.1-pg{pg}-x64.zip"
        for key, val in (
            ("sourceGroup", "external"), ("extension", "hypopg"), ("pgMajor", pg),
            ("sourceRepo", "HypoPG/hypopg"), ("repositoryId", 37308208),
            ("releaseTag", "1.4.1"), ("releaseId", 153113229),
            ("assetName", name), ("assetId", aid), ("originalBytes", size),
            ("originalSha256", sha),
            ("originalProviderUrl", f"https://github.com/HypoPG/hypopg/releases/download/1.4.1/{name}"),
            ("licenseUrl", "https://github.com/HypoPG/hypopg/blob/1.4.1/LICENSE"),
            ("approvedOperation", OP), ("downloadAuthorized", True),
            ("mirrorAuthorized", False),
        ):
            require(type(row[key]) is type(val) and row[key] == val,
                    "unknown signed HypoPG exact-asset source: " + key)
        require(all(type(row[k]) is str and len(row[k]) >= 60
                    for k in ("targetEnvironment", "noticeTreatment", "dependencyTreatment"))
                and "PostgreSQL " + pg in row["targetEnvironment"]
                and "Windows x64" in row["targetEnvironment"],
                "unreviewed PG ABI/NOTICE/dependency in signed record")

def validate_portalcorp_records(rows):
    """Only the independently reviewed original portalcorp v0.8.0 PG16 ZIP."""
    require(type(rows) is list and len(rows) == 1
            and type(rows[0]) is dict and set(rows[0]) == ROW_KEYS,
            "unreviewed portalcorp cohort structure")
    row = rows[0]
    expected = {
        "sourceGroup": "external", "extension": "vector", "pgMajor": "16",
        "sourceRepo": "portalcorp/pgvector_compiled", "repositoryId": 835861704,
        "releaseTag": "v0.16.105", "releaseId": 182821763,
        "assetId": 203009337, "assetName": "pgvector-x86_64-pc-windows-msvc-pg16.zip",
        "originalBytes": 163732,
        "originalSha256": "a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571",
        "originalProviderUrl": "https://github.com/portalcorp/pgvector_compiled/releases/download/v0.16.105/pgvector-x86_64-pc-windows-msvc-pg16.zip",
        "licenseUrl": "https://github.com/portalcorp/pgvector_compiled/blob/v0.16.105/LICENSE",
        "approvedOperation": OP, "downloadAuthorized": True, "mirrorAuthorized": False,
    }
    for key, val in expected.items():
        require(type(row[key]) is type(val) and row[key] == val,
                "wrong portalcorp source-specific immutable pin: " + key)
    require("PostgreSQL 16" in row["targetEnvironment"]
            and "Windows x64" in row["targetEnvironment"]
            and all(type(row[k]) is str and len(row[k]) >= 60
                    for k in ("targetEnvironment", "noticeTreatment", "dependencyTreatment"))
            and "https://github.com/pgvector/pgvector/blob/v0.8.0/LICENSE"
                in row["noticeTreatment"], "portalcorp runtime or source NOTICE missing")


def validate_reviewed_pg18_records(rows):
    """Two immutable PG18 originals reviewed independently before owner signing."""
    pins = (
        ("laurenz/oracle_fdw", "oracle_fdw", 14332609, 335861225,
         "ORACLE_FDW_2_9_0", 442625860, "oracle_fdw-2.9.0-pg18-win64.zip",
         365101, "ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678",
         "https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE"),
        ("andreiramani/pgvector_pgsql_windows", "pgvector", 838202416,
         419235203, "0.8.7", 661612613, "vector.v0.8.7-pg18.zip",
         174796, "7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d",
         "https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE"),
    )
    require(type(rows) is list and len(rows) == 2,
            "unreviewed PG18 source count")
    for row, (repo, extension, repo_id, release_id, tag, asset_id, name,
              size, sha, license_url) in zip(rows, pins):
        require(type(row) is dict and set(row) == ROW_KEYS,
                "unreviewed PG18 record fields")
        fixed = {
            "sourceGroup": "external", "extension": extension, "pgMajor": "18",
            "sourceRepo": repo, "repositoryId": repo_id, "releaseId": release_id,
            "releaseTag": tag, "assetId": asset_id, "assetName": name,
            "originalBytes": size, "originalSha256": sha,
            "originalProviderUrl":
                f"https://github.com/{repo}/releases/download/{tag}/{name}",
            "licenseUrl": license_url, "approvedOperation": OP,
            "downloadAuthorized": True, "mirrorAuthorized": False,
        }
        require(all(type(row[key]) is type(value) and row[key] == value
                    for key, value in fixed.items())
                and "PostgreSQL 18" in row["targetEnvironment"]
                and "Windows x64" in row["targetEnvironment"]
                and all(type(row[key]) is str and len(row[key]) >= 100
                        for key in ("targetEnvironment", "noticeTreatment",
                                    "dependencyTreatment") if key != "targetEnvironment"),
                "unreviewed PG18 source, license, NOTICE or dependency")
        if extension == "oracle_fdw":
            require("Oracle Instant Client" in row["noticeTreatment"]
                    and "www.oracle.com/downloads/licenses/instant-client-lic.html"
                    in row["dependencyTreatment"], "missing Oracle dependency license")
        else:
            require("no LICENSE/NOTICE" in row["noticeTreatment"]
                    and "Unofficial" in row["dependencyTreatment"],
                    "missing unofficial pgvector attribution")


def gh_read(route):
    require(re.fullmatch(
        r"repos/pgextwin/build/actions/runs/[1-9][0-9]{0,14}(?:/jobs\?per_page=100|/approvals)?",
        route) is not None, "unexpected GitHub API route")
    p = subprocess.run(["gh", "api", "--method", "GET", route],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False)
    require(p.returncode == 0 and 0 < len(p.stdout) < 3000000, "authenticated Build GET unavailable")
    return json.loads(p.stdout, object_pairs_hook=unique)

def verify_online(entry, doc):
    runid = doc["issuerRunId"]
    base = f"repos/pgextwin/build/actions/runs/{runid}"
    run = gh_read(base)
    require(run.get("id") == runid
            and run.get("run_attempt") == 1
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == ".github/workflows/external-direct-get-issuer.yml"
            and run.get("head_branch") == "main"
            and run.get("head_sha") == doc["issuerCommit"]
            and run.get("repository", {}).get("full_name") == "pgextwin/build"
            and run.get("actor", {}).get("login") == "ShutenOishi"
            and run.get("actor", {}).get("id") == 27071164
            and run.get("triggering_actor", {}).get("login") == "ShutenOishi"
            and ((run.get("status") == "completed" and run.get("conclusion") == "success")
                 or (run.get("status") == "in_progress" and run.get("conclusion") is None)),
            "original owner Build Run/attempt did not match")
    jobs = gh_read(base + "/jobs?per_page=100").get("jobs", [])
    by_name = {j.get("name"): j for j in jobs}
    require(all(by_name.get(n, {}).get("conclusion") == "success"
                and by_name[n].get("run_id") == runid
                for n in ("issue-and-attest", "independent-verify")),
            "original same-Run independent verification not successful")
    if run.get("status") == "completed":
        require(by_name.get("propose-public-pin-pr", {}).get("conclusion") == "success",
                "genuine App proposal job not successful")
    approvals = gh_read(base + "/approvals")
    require(type(approvals) is list and any(
        a.get("state") == "approved"
        and a.get("user", {}).get("login") == "ShutenOishi"
        and a.get("user", {}).get("id") == 27071164
        and any(x.get("id") == 26208765001
                and x.get("name") == "external-direct-provider-publisher"
                for x in a.get("environments", []))
        for a in approvals), "no genuine owner Environment approval")
    p = subprocess.run([
        "gh", "attestation", "verify", str(entry / "external-get-admission.json"),
        "--repo", "pgextwin/build", "--bundle", str(entry / "attestation.json"),
        "--signer-workflow", "pgextwin/build/.github/workflows/external-direct-get-issuer.yml",
        "--source-ref", "refs/heads/main", "--source-digest", doc["issuerCommit"],
        "--deny-self-hosted-runners", "--format", "json",
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=120)
    require(p.returncode == 0 and 2 <= len(p.stdout) <= 5000000,
            "original signed bytes / Sigstore identity verification failed")
    verified = json.loads(p.stdout, object_pairs_hook=unique)
    require(type(verified) is list and len(verified) >= 1,
            "zero matching independently verified attestations")

def validate_latest_pointer(pointer, admission_bytes, dirname):
    require(type(pointer) is dict and set(pointer) == LATEST_KEYS,
            "unknown Catalog latest external pin schema")
    match = RUN_DIR.fullmatch(dirname)
    require(match is not None and pointer.get("schemaVersion") == LATEST_SCHEMA
            and type(pointer.get("issuerRunId")) is int
            and pointer["issuerRunId"] == int(match.group(1)),
            "Catalog latest pointer does not select this signed Run")
    require(type(pointer.get("admissionSha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", pointer["admissionSha256"]) is not None
            and pointer["admissionSha256"] == hashlib.sha256(admission_bytes).hexdigest(),
            "Catalog latest pointer does not bind the exact signed admission bytes")
    signed = json.loads(admission_bytes, object_pairs_hook=unique)
    current = pointer.get("records")
    require(type(current) is list and 1 <= len(current) <= 20
            and type(signed.get("records")) is list
            and len(current) == len(signed["records"]),
            "Catalog latest pin set is incomplete or oversized")
    signed_by_key = {}
    for row in signed["records"]:
        key = (row.get("extension"), row.get("pgMajor"))
        require(key not in signed_by_key, "duplicate signed latest binary")
        signed_by_key[key] = row
    seen = set()
    for row in current:
        require(type(row) is dict and set(row) == LATEST_ROW_KEYS,
                "unknown Catalog latest pin fields")
        key = (row.get("extension"), row.get("pgMajor"))
        require(key not in seen and key in signed_by_key,
                "duplicate or unsigned Catalog latest binary")
        seen.add(key)
        signed_row = signed_by_key[key]
        require(all(type(row.get(name)) is type(signed_row.get(name))
                    and row[name] == signed_row[name]
                    for name in LATEST_ROW_KEYS),
                "Catalog latest release identity differs from owner-signed admission")
    require(seen == set(signed_by_key),
            "Catalog latest pin set omits a signed external binary")

def scan(root, *, now, online=True):
    parent = Path(root) / "external/signed-direct-get"
    if not parent.exists():
        return []
    require(parent.is_dir() and not parent.is_symlink(), "unsafe source pin parent")
    names = {x.name for x in parent.iterdir()}
    require(bool(names) and names <= {"pg_trickle", "hypopg", "portalcorp_pgvector", "qualified_cohort"},
            "unknown or unapproved signed original provider")
    outputs = []
    for source_name in sorted(names):
        source = parent / source_name
        require(source.is_dir() and not source.is_symlink(),
                "unsafe signed source directory")
        children = list(source.iterdir())
        latest_bytes = None
        if source_name == "qualified_cohort":
            latest_path = source / LATEST_NAME
            require(latest_path in children and latest_path.is_file()
                    and not latest_path.is_symlink()
                    and 100 < latest_path.stat().st_size < 200000,
                    "missing or invalid Catalog latest external pin index")
            latest_bytes = latest_path.read_bytes()
            children = [item for item in children if item != latest_path]
        entries = sorted(children, key=lambda p: p.name)
        require(len(entries) <= 50, "unbounded signed source archive history")
        admissions = {}
        for entry in entries:
            require(entry.is_dir() and not entry.is_symlink()
                    and RUN_DIR.fullmatch(entry.name) is not None, "unexpected pin directory")
            require({p.name for p in entry.iterdir()} == FILES,
                    "incomplete or tampered two-file signed metadata")
            for filename in FILES:
                p = entry / filename
                require(p.is_file() and not p.is_symlink()
                        and 100 < p.stat().st_size < 200000,
                        "invalid signed metadata bytes")
            doc = json.loads((entry / "external-get-admission.json").read_bytes(),
                             object_pairs_hook=unique)
            admission_bytes = (entry / "external-get-admission.json").read_bytes()
            status = validate_document(doc, entry.name, now=now, source=source_name)
            if online:
                verify_online(entry, doc)
            admissions[entry.name] = admission_bytes
            outputs.append({"runId": doc["issuerRunId"], "source": source_name,
                            "status": status, "mirrorAuthorized": False,
                            "redistributionAuthorized": False})
        if source_name == "qualified_cohort":
            pointer = json.loads(latest_bytes, object_pairs_hook=unique)
            require(type(pointer) is dict and type(pointer.get("issuerRunId")) is int,
                    "Catalog latest external pin index has no numeric Run")
            run_dir = "run-" + str(pointer.get("issuerRunId", ""))
            require(run_dir in admissions,
                    "Catalog latest pointer targets no archived signed Run")
            validate_latest_pointer(pointer, admissions[run_dir], run_dir)
    return outputs

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=ROOT)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        rows = scan(args.catalog, now=datetime.now(timezone.utc),
                    online=not args.offline)
        print(f"ORIGINAL_GET_SIGNED_PUBLIC_CATALOG_PIN_VALIDATED={len(rows)} "
              f"ACTIVE={sum(x['status']=='ACTIVE' for x in rows)} "
              "MIRROR_DENY=TRUE REDISTRIBUTION_DENY=TRUE "
              "EXPIRED_ARCHIVE_IS_NOT_AUTHORIZATION")
    except Exception:
        print("ORIGINAL_GET_SIGNED_PUBLIC_CATALOG_PIN_DENY; unsigned/mismatched/unknown pin",
              file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
