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

def validate_document(doc, dirname, *, now):
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
    return "ACTIVE" if issued <= now < expiry else "EXPIRED_ARCHIVE_DOWNLOAD_DENY"

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

def scan(root, *, now, online=True):
    parent = Path(root) / "external/signed-direct-get"
    if not parent.exists():
        return []
    require(parent.is_dir() and not parent.is_symlink(), "unsafe source pin parent")
    require({x.name for x in parent.iterdir()} == {"pg_trickle"},
            "unknown or unapproved public signed pin source")
    source = parent / "pg_trickle"
    require(source.is_dir() and not source.is_symlink(), "unsafe source subdirectory")
    entries = sorted(source.iterdir(), key=lambda p: p.name)
    require(len(entries) <= 50, "unbounded pin history")
    outputs = []
    for entry in entries:
        require(entry.is_dir() and not entry.is_symlink()
                and RUN_DIR.fullmatch(entry.name) is not None, "unexpected pin directory")
        require({p.name for p in entry.iterdir()} == FILES,
                "incomplete/tampered signed two-file metadata")
        for filename in FILES:
            p = entry / filename
            require(p.is_file() and not p.is_symlink()
                    and 100 < p.stat().st_size < 200000,
                    "unexpected signed metadata bytes")
        doc = json.loads((entry / "external-get-admission.json").read_bytes(),
                         object_pairs_hook=unique)
        status = validate_document(doc, entry.name, now=now)
        if online:
            verify_online(entry, doc)
        outputs.append({"runId": doc["issuerRunId"], "status": status,
                        "mirrorAuthorized": False, "redistributionAuthorized": False})
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
