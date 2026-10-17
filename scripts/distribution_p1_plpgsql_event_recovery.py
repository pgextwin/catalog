#!/usr/bin/env python3
"""Issue #112: exact plpgsql_check published-Event recovery evidence (fail closed).

This is NOT a failed-Run waiver. The normal P1 signed_run/fetch_jobs remain
unchanged. No admission is possible until an independently fixed event digest,
a separately corroborated authorization-to-publication causal link, and five
genuine offline TUF/SLSA/SPDX checks exist. The capture subcommand is GET-only
and never emits a trust verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from zipfile import BadZipFile, ZipFile

from distribution_manifest_v1 import Denied, require, strict_json, verify_archive_members
from distribution_release_verify_p1 import (
    PROVENANCE, SPDX, sha, verify_sigstore_offline,
)

REPO = "pgextwin/plpgsql_check"
REPO_ID = 1410581312
RELEASE_ID = 409572202
TAG = "v2.10.14-windows.1"
PACKAGING = "37cb5ee00f556fd6b57e439a5e19cd210125a571"
RUN_ID = 38128142145
PUBLISH_JOB = 114438997591
EVENT_ID = "16939274945"
ACTOR_ID = 41898282
EVENT_TIME = "2026-10-11T10:46:26Z"
SIGNER = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
ORIGINAL_JOBS = {14: 114436765036, 15: 114436765058,
                 16: 114436765083, 17: 114436765086, 18: 114436765070}
ARTIFACTS = {
    "promotion-receipt": (11698050284, "132e7bad81707344e8fd9d433cde4a161144417b843620c684ae8088615d8856"),
    "promotion-recovery": (11698336665, "5316ef1674098697da65bf9780390e313ff8da9a61db2def86c2b72ad765dfd6"),
}
PG_ZIPS = {
    14: "c12870b33aa62c8743c86864342b9737b7cde714cb9305358fb30aaaf5fa3444",
    15: "6df7494ed604b29733f9fee2fc09e1770b6ef9b5ca6ed7543d07ae2be8e4b55f",
    16: "e1f02b18b5a1ba88e12b5f2cff21223cfbc969935803496b0f754876aeb12f2c",
    17: "f876dbffea9892823f3e429457a6367f95d8981ebb78121f688e4d45282c5659",
    18: "d60202dea1464f1152f0f476a051bf5960af3f898149960addc1d541e87b0138",
}
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
ROOT = Path(__file__).resolve().parents[1]
ANCHOR = ROOT / "evidence/p1/plpgsql-published-event-recovery-pending-v1.json"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode("utf-8")


def event_snapshot(event):
    """Extract explicitly specified immutable facts, never event-page positions."""
    require(type(event) is dict and event.get("id") == EVENT_ID
            and event.get("type") == "ReleaseEvent"
            and event.get("created_at") == EVENT_TIME,
            "missing/different published ReleaseEvent identity")
    repo = event.get("repo") or {}
    actor = event.get("actor") or {}
    payload = event.get("payload") or {}
    release = payload.get("release") or {}
    require(repo.get("id") == REPO_ID and repo.get("name") == REPO
            and actor.get("id") == ACTOR_ID
            and actor.get("login") == "github-actions[bot]"
            and payload.get("action") == "published"
            and release.get("id") == RELEASE_ID
            and release.get("tag_name") == TAG
            and release.get("target_commitish") == PACKAGING
            and release.get("draft") is False
            and release.get("published_at") == EVENT_TIME,
            "Event repo/actor/action/Release/target SHA substitution")
    return {"schema": "pgextwin-plpgsql-published-event-canonical/v1",
            "eventId": EVENT_ID, "type": "ReleaseEvent",
            "action": "published", "createdAt": EVENT_TIME,
            "actor": {"id": ACTOR_ID, "login": "github-actions[bot]"},
            "repository": {"id": REPO_ID, "name": REPO},
            "release": {"id": RELEASE_ID, "tag": TAG,
                        "targetSha": PACKAGING, "draft": False,
                        "publishedAt": EVENT_TIME}}


def verify_event_snapshot(snapshot_bytes, pinned_sha):
    """Pin must come from protected, independently audited policy, not snapshot."""
    require(type(pinned_sha) is str and HEX64.fullmatch(pinned_sha),
            "BLOCKED: external event canonical SHA256 not fixed")
    require(type(snapshot_bytes) is bytes and len(snapshot_bytes) < 65536
            and hashlib.sha256(snapshot_bytes).hexdigest() == pinned_sha,
            "event canonical bytes do not match trusted anchor")
    snapshot = strict_json(snapshot_bytes)
    require(type(snapshot) is dict and canonical(snapshot) == snapshot_bytes,
            "noncanonical/replayed event bytes")
    require(snapshot == event_snapshot({
        "id": snapshot.get("eventId"), "type": snapshot.get("type"),
        "created_at": snapshot.get("createdAt"),
        "repo": snapshot.get("repository"),
        "actor": snapshot.get("actor"),
        "payload": {"action": snapshot.get("action"),
                    "release": {
                        "id": (snapshot.get("release") or {}).get("id"),
                        "tag_name": (snapshot.get("release") or {}).get("tag"),
                        "target_commitish": (snapshot.get("release") or {}).get("targetSha"),
                        "draft": (snapshot.get("release") or {}).get("draft"),
                        "published_at": (snapshot.get("release") or {}).get("publishedAt"),
                    }}}), "event snapshot schema/identity changed")
    return snapshot


def capture_event_get_only():
    """Candidate evidence capture; no authentication or admission claim."""
    for page in (1, 2, 3):
        path = f"repos/{REPO}/events?per_page=100&page={page}"
        try:
            proc = subprocess.run(("gh", "api", "--method", "GET", path),
                                  capture_output=True, timeout=90,
                                  env={**os.environ, "GH_PROMPT_DISABLED": "1",
                                       "GH_NO_UPDATE_NOTIFIER": "1"}, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Denied("BLOCKED: safe GET-only Event API inaccessible") from exc
        require(proc.returncode == 0 and 0 < len(proc.stdout) <= 8*1024*1024,
                "BLOCKED: safe GET-only Event API refused or oversized")
        events = strict_json(proc.stdout)
        require(type(events) is list and len(events) <= 100,
                "unexpected events-page structure")
        matching = [x for x in events if type(x) is dict and x.get("id") == EVENT_ID]
        require(len(matching) <= 1, "duplicate event ID")
        if matching:
            return canonical(event_snapshot(matching[0]))
    raise Denied("BLOCKED: exact ReleaseEvent not present in bounded GET pages")


def validate_original_run(run, jobs):
    """Assert original FAILURE and five successful builds; NEVER waive publisher."""
    require(type(run) is dict and run.get("id") == RUN_ID
            and run.get("run_attempt") == 1
            and run.get("head_sha") == PACKAGING
            and (run.get("repository") or {}).get("id") == REPO_ID
            and (run.get("repository") or {}).get("full_name") == REPO
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == ".github/workflows/promote.yml"
            and run.get("head_branch") == "main"
            and run.get("status") == "completed"
            and run.get("conclusion") == "failure",
            "original promotion failure identity was changed or waived")
    require(type(jobs) is dict and type(jobs.get("jobs")) is list
            and jobs.get("total_count") == len(jobs["jobs"])
            and len(jobs["jobs"]) <= 100,
            "partial original jobs")
    all_jobs = jobs["jobs"]
    require(len({j.get("id") for j in all_jobs}) == len(all_jobs),
            "duplicate original Jobs")
    for pg, job_id in ORIGINAL_JOBS.items():
        matches = [j for j in all_jobs if j.get("id") == job_id]
        require(len(matches) == 1
                and f"PostgreSQL {pg} / Windows x64" in matches[0].get("name", "")
                and matches[0].get("conclusion") == "success"
                and matches[0].get("run_attempt") == 1,
                "original PG build job missing/not successful")
    publication = [j for j in all_jobs if j.get("id") == PUBLISH_JOB]
    require(len(publication) == 1
            and publication[0].get("name") ==
                "Verify signatures and SHA; create-only formal publication"
            and publication[0].get("conclusion") == "failure"
            and publication[0].get("run_attempt") == 1,
            "original failed publisher was forged as success")
    return True


def validate_original_release(release, asset_ids, expected_digests):
    require(type(release) is dict and release.get("id") == RELEASE_ID
            and release.get("tag_name") == TAG
            and release.get("target_commitish") == PACKAGING
            and release.get("draft") is False
            and release.get("prerelease") is False
            and release.get("published_at") == EVENT_TIME,
            "wrong public release")
    assets = release.get("assets")
    require(type(assets) is list and len(assets) == 16
            and type(asset_ids) is dict and len(asset_ids) == 16
            and type(expected_digests) is dict and len(expected_digests) == 16,
            "incomplete public 16-asset set")
    observed = {}
    for asset in assets:
        require(type(asset) is dict and type(asset.get("name")) is str
                and asset.get("state") == "uploaded"
                and type(asset.get("id")) is int
                and isinstance(asset.get("digest"), str)
                and re.fullmatch(r"sha256:[a-f0-9]{64}", asset["digest"])
                and asset["name"] not in observed, "bad public asset")
        observed[asset["name"]] = asset
    require(set(observed) == set(asset_ids) == set(expected_digests)
            and all(observed[n]["id"] == v for n,v in asset_ids.items())
            and all(observed[n]["digest"] == "sha256:" + digest
                    and type(digest) is str and HEX64.fullmatch(digest)
                    for n, digest in expected_digests.items()),
            "public original Asset ID/digest missing/replaced")
    for pg, digest in PG_ZIPS.items():
        names = [n for n in observed if n.endswith(f"-pg{pg}-windows-x64.zip")]
        require(len(names) == 1
                and observed[names[0]]["digest"] == "sha256:" + digest,
                "PG ZIP substituted")
    return observed


def validate_artifact_metadata(artifacts):
    require(type(artifacts) is list, "missing original artifact metadata")
    for name, (number, digest) in ARTIFACTS.items():
        matching = [a for a in artifacts
                    if a.get("id") == number and a.get("name") == name]
        require(len(matching) == 1 and matching[0].get("expired") is False
                and matching[0].get("digest") == "sha256:" + digest,
                "original approval/recovery transport artifact mismatch")
    return True


def original_json_archive(path, name):
    """Read original transport ZIP; its checksum is NOT a signature."""
    expected = ARTIFACTS[name][1]
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024*1024
            and sha(path) == expected, "BLOCKED: original artifact ZIP byte SHA mismatch")
    try:
        with ZipFile(path) as z:
            verify_archive_members(z)
            files = [f for f in z.infolist() if not f.is_dir()]
            require(len(files) == 1 and files[0].filename.endswith(".json")
                    and files[0].file_size <= 65536,
                    "original artifact archive not exactly one bounded JSON")
            return strict_json(z.read(files[0]))
    except (OSError, BadZipFile, ValueError, RuntimeError) as exc:
        raise Denied("BLOCKED: original archive invalid/CRC failure") from exc


def validate_recovery_artifacts(approval, recovery):
    """Do not infer later PATCH authorization from an earlier PUBLISH input."""
    require(type(approval) is dict and type(recovery) is dict
            and recovery.get("state") == "DRAFT_STAGED"
            and recovery.get("runId") == RUN_ID
            and recovery.get("tag") == TAG
            and recovery.get("commit") == PACKAGING
            and "PUBLISH" in canonical(approval).decode("utf-8")
            and "VERIFIED_MANUAL_DISPATCH" in canonical(approval).decode("utf-8"),
            "original PUBLISH approval or DRAFT_STAGED recovery mismatch")
    return True


def require_causal_bridge(anchor):
    """Fail closed: Event actor alone cannot establish token or PATCH causality."""
    require(type(anchor) is dict
            and anchor.get("schema") == "pgextwin-plpgsql-recovery-anchor/v1"
            and anchor.get("repositoryId") == REPO_ID
            and anchor.get("releaseId") == RELEASE_ID
            and anchor.get("runId") == RUN_ID
            and anchor.get("runAttempt") == 1
            and anchor.get("packagingSha") == PACKAGING,
            "untrusted recovery anchor")
    require(anchor.get("eventCanonicalSha256") is not None
            and anchor.get("causalBridgeIndependentlyVerified") is True
            and type(anchor.get("causalBridgeEvidenceSha256")) is str
            and HEX64.fullmatch(anchor["causalBridgeEvidenceSha256"]),
            "BLOCKED: no independently fixed publication-to-PUBLISH causal bridge")
    # This profile deliberately has no accepted authenticated causal bridge
    # record yet. Self-asserted flags and digests can NEVER authorize release.
    raise Denied("BLOCKED: missing independent authenticated causal audit validator")


def verify_original_pg_sigstore(*, pg, zip_path, sbom_path, bundle_path,
                                bundle_sha256, root_path, root_sha256):
    """Real offline dual gh/TUF verification; not an Event/receipt substitute."""
    require(type(pg) is int and pg in ORIGINAL_JOBS
            and zip_path.is_file() and not zip_path.is_symlink()
            and sha(zip_path) == PG_ZIPS[pg],
            "original PG original ZIP wrong")
    require(sbom_path.is_file() and not sbom_path.is_symlink(),
            "original public SPDX missing")
    sbom = strict_json(sbom_path.read_bytes())
    require(sbom.get("spdxVersion") == "SPDX-2.3",
            "original SBOM version mismatch")
    result = verify_sigstore_offline(
        zip_path, sbom, repo=REPO, repo_id=REPO_ID, packaging_sha=PACKAGING,
        signer_sha=SIGNER, run_id=RUN_ID, attempt=1, root_path=root_path,
        root_sha=root_sha256, bundles={
            PROVENANCE: (bundle_path, bundle_sha256),
            SPDX: (bundle_path, bundle_sha256)})
    require(result.get("signatureVerified") is True,
            "genuine SLSA v1 and SPDX 2.3 did not both verify")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-event", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    require(args.capture_event and args.output is not None,
            "only GET-only event capture is an enabled command")
    require(not args.output.exists() and not args.output.is_symlink(),
            "do not overwrite existing event evidence")
    raw = capture_event_get_only()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as f:
        f.write(raw)
    print(json.dumps({"status":"OBSERVATION_ONLY_NOT_ACCEPTED",
                      "eventId": EVENT_ID,
                      "canonicalSha256": hashlib.sha256(raw).hexdigest(),
                      "file": str(args.output),
                      "p1FormalAccepted": 65, "p1Total": 70,
                      "distributionAuthorized": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Denied, OSError, ValueError) as exc:
        raise SystemExit("DENY: " + str(exc)) from exc
