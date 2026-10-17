#!/usr/bin/env python3
"""Issue #112 exact plpgsql five original ZIP dual-Sigstore, read-only pilot.

Runs only under an authenticated, SHA-pinned official gh CLI and TUF policy.
Outputs diagnostic evidence, never a formal acceptance. No writes to GitHub.
Missing/expired Artifacts, Event, proof or genuine signatures fail closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_batch import require_gh, fresh_root, obtain_assets
from distribution_release_audit_p1 import api_json, policy_load, pinned_content, resolve_tag, gh_read
from distribution_release_verify_p1 import (
    PROVENANCE, SPDX, release_assets, rehash_release, require_asset_id_pins,
    verified_catalog, sha, immutable_source, inspect_package,
)
from distribution_p1_plpgsql_event_recovery import (
    REPO, REPO_ID, RUN_ID, PACKAGING, RELEASE_ID, SIGNER,
    PG_ZIPS, ORIGINAL_JOBS, BUILD_ARTIFACTS, ARTIFACTS,
    capture_event_get_only, validate_artifact_metadata,
    validate_original_run, validate_original_release,
    original_json_archive, validate_recovery_artifacts,
    verify_original_build_archive, verify_original_pg_sigstore,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config/issue112-p1-fleet-pins-20261017.json"


def official_original_get_bytes(path):
    """Only the seven exact original artifact ZIP GET endpoints."""
    allowed = {id for id, digest in BUILD_ARTIFACTS.values()}
    allowed.update(id for id, digest in ARTIFACTS.values())
    matched = re.fullmatch(
        r"repos/pgextwin/plpgsql_check/actions/artifacts/([1-9][0-9]*)/zip", path)
    require(matched and int(matched[1]) in allowed, "unsafe artifact GET")
    try:
        result = subprocess.run(("gh","api","--method","GET",path),
                                capture_output=True, timeout=180,
                                env={**os.environ, "GH_PROMPT_DISABLED": "1",
                                     "GH_NO_UPDATE_NOTIFIER": "1"}, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Denied("BLOCKED: original GitHub Artifact GET inaccessible") from exc
    require(result.returncode == 0 and 0 < len(result.stdout) < 1024*1024,
            "BLOCKED: original Artifact download failed or too large")
    return result.stdout


def original_artifacts(folder):
    for pg, (id, digest) in BUILD_ARTIFACTS.items():
        raw = official_original_get_bytes(
            f"repos/{REPO}/actions/artifacts/{id}/zip")
        require(hashlib.sha256(raw).hexdigest() == digest,
                "BLOCKED: original Build Artifact transport digest mismatch")
        (folder / f"build-pg{pg}.zip").write_bytes(raw)
    for name, (id, digest) in ARTIFACTS.items():
        raw = official_original_get_bytes(
            f"repos/{REPO}/actions/artifacts/{id}/zip")
        require(hashlib.sha256(raw).hexdigest() == digest,
                "BLOCKED: original manual approval/recovery ZIP digest mismatch")
        (folder / (name + ".zip")).write_bytes(raw)


def read_original_json(path):
    allowed = {
        f"repos/{REPO}/actions/runs/{RUN_ID}/attempts/1",
        f"repos/{REPO}/actions/runs/{RUN_ID}/attempts/1/jobs?per_page=100",
        f"repos/{REPO}/actions/runs/{RUN_ID}/artifacts?per_page=100",
    }
    require(path in allowed, "unsafe original-run metadata GET")
    try:
        proc = subprocess.run(("gh","api","--method","GET",path),
                              capture_output=True, timeout=90,
                              env={**os.environ, "GH_PROMPT_DISABLED":"1",
                                   "GH_NO_UPDATE_NOTIFIER":"1"}, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Denied("BLOCKED: original-run metadata GET inaccessible") from exc
    require(proc.returncode == 0 and 0 < len(proc.stdout) < 8*1024*1024,
            "BLOCKED: original-run metadata query refused")
    return strict_json(proc.stdout)


def execute():
    policy = policy_load(POLICY)
    require(policy["repoIds"]["plpgsql_check"] == REPO_ID
            and policy["releaseIds"]["plpgsql_check"] == RELEASE_ID
            and SIGNER in policy["trustedSignerShas"],
            "original signer/repository/release policy not pinned")
    gh = require_gh(policy)
    index = pinned_content("catalog","index.json",policy["catalogCommitSha"])
    entries = strict_json(index)["extensions"]
    records = {name:pinned_content("catalog",f"extensions/{name}.json",
                                   policy["catalogCommitSha"])
               for name in entries}
    record = verified_catalog(index,records,policy["catalogDigests"],
                              policy["catalogCommitSha"])["plpgsql_check"]
    release = api_json("plpgsql_check/releases/tags/" +
                       record["latest"]["releaseTag"])
    assets = release_assets(record,release,RELEASE_ID,REPO_ID)
    require_asset_id_pins(assets,policy["assetIds"]["plpgsql_check"])
    digest_pins = {name: record["postgresql"][str(pg)]["sha256"]
                   for pg in PG_ZIPS
                   for name in [record["postgresql"][str(pg)]["asset"]]}
    for pg in PG_ZIPS:
        row = record["postgresql"][str(pg)]
        for key in ("sbom","vulnerabilityReport"):
            entry = row["evidence"][key]
            digest_pins[entry["asset"]] = entry["sha256"]
    # SHA256SUMS is pinned by immutable Release ID+Asset ID+digest metadata,
    # and then by genuine raw bytes in rehash_release.
    digest_pins["SHA256SUMS.txt"] = assets["SHA256SUMS.txt"]["digest"][7:]
    validated = validate_original_release(release,policy["assetIds"]["plpgsql_check"],
                                          digest_pins)
    require(resolve_tag("plpgsql_check",release["tag_name"]) == PACKAGING,
            "original signed release tag ref mismatch")
    run = read_original_json(f"repos/{REPO}/actions/runs/{RUN_ID}/attempts/1")
    jobs = read_original_json(f"repos/{REPO}/actions/runs/{RUN_ID}/attempts/1/jobs?per_page=100")
    validate_original_run(run,jobs)
    listing = read_original_json(f"repos/{REPO}/actions/runs/{RUN_ID}/artifacts?per_page=100")
    require(type(listing.get("artifacts")) is list
            and listing.get("total_count") == len(listing["artifacts"])
            and len(listing["artifacts"]) <= 100,
            "incomplete original seven Artifact metadata")
    validate_artifact_metadata(listing["artifacts"])
    with tempfile.TemporaryDirectory(prefix="issue112-plpgsql-readonly-") as tmp:
        folder = Path(tmp)
        pub = folder / "published-original"
        pub.mkdir()
        cache = folder / "content-addressed"
        cache.mkdir()
        obtain_assets(cache,pub,assets,REPO,release["tag_name"])
        hashes = rehash_release(pub,assets,record)
        require(all(hashes[record["postgresql"][str(pg)]["asset"]] ==
                    PG_ZIPS[pg] for pg in ORIGINAL_JOBS),
                "original release rehash differed from exact PG pins")
        evidence = folder / "original-action-artifacts"
        evidence.mkdir()
        original_artifacts(evidence)
        approval = original_json_archive(evidence / "promotion-receipt.zip",
                                         "promotion-receipt")
        staged = original_json_archive(evidence / "promotion-recovery.zip",
                                       "promotion-recovery")
        validate_recovery_artifacts(approval,staged)
        config = strict_json(pinned_content("plpgsql_check","config/extension.json",
                                            PACKAGING))
        trusted_root = fresh_root(policy,folder / "trusted-tuf-root.json")
        sig_results = {}
        for pg in sorted(ORIGINAL_JOBS):
            major = str(pg)
            triple = verify_original_build_archive(pg,evidence/f"build-pg{pg}.zip",
                                                   validated)
            row = record["postgresql"][major]
            zip_path = pub / row["asset"]
            sbom_path = pub / row["evidence"]["sbom"]["asset"]
            src = immutable_source(config,pg,record)
            pkg = inspect_package(zip_path,sbom_path,
                                  pub / row["evidence"]["vulnerabilityReport"]["asset"],
                                  repository=REPO,major=pg,
                                  immutable_packaging_sha=PACKAGING,source=src)
            require(pkg["runId"] == RUN_ID and pkg["runAttempt"] == 1
                    and pkg["signerSha"] == SIGNER,
                    "actual PG ZIP run/attempt/signer mismatch")
            attest_dir = folder / f"attest-pg{pg}"
            attest_dir.mkdir()
            gh_read("attestation","download",str(zip_path.resolve()),
                    "--repo",REPO,cwd=attest_dir)
            bundle = next((p for p in (
                attest_dir / ("sha256:" + PG_ZIPS[pg] + ".jsonl"),
                attest_dir / ("sha256-" + PG_ZIPS[pg] + ".jsonl"))
                if p.is_file() and not p.is_symlink()),None)
            require(bundle is not None,"BLOCKED: missing original dual Sigstore bundle")
            bundle_hash = sha(bundle)
            crypto = verify_original_pg_sigstore(
                pg=pg,zip_path=zip_path,sbom_path=sbom_path,
                bundle_path=bundle,bundle_sha256=bundle_hash,
                root_path=trusted_root,root_sha256=policy["rootSha256"])
            require(crypto["signatureVerified"] is True,
                    "original PG true SLSA/SPDX dual-signature failed")
            sig_results[major] = {
                "originalBuildArtifactId": BUILD_ARTIFACTS[pg][0],
                "originalBuildJobId": ORIGINAL_JOBS[pg],
                "publishedZipAssetId": validated[row["asset"]]["id"],
                "publishedZipSha256": hashes[row["asset"]],
                "originalInnerHashes": triple,
                "bundleSha256": bundle_hash, "genuineDualSigstore": True}
        # Event is distinct from signatures; a later event may no longer be
        # on the rolling Events API. If unavailable, fail closed.
        event = capture_event_get_only()
        return {"schema":"pgextwin-plpgsql-original-recovery-diagnostic/v1",
                "status":"OBSERVATION_ONLY_NOT_FORMAL_ACCEPTANCE",
                "officialGhSha256":gh["binarySha256"],
                "trustedRootSha256":policy["rootSha256"],
                "runId":RUN_ID,"runAttempt":1,"runConclusion":"failure",
                "publishJobConclusion":"failure",
                "releaseId":RELEASE_ID,"releaseAssetCount":len(hashes),
                "eventCanonicalSha256":hashlib.sha256(event).hexdigest(),
                "pgResults":sig_results,"verifiedPgCount":len(sig_results),
                "causalBridgeIndependentlyVerified":False,
                "p1FormalAccepted":65,"historicalSourceFormalAccepted":40,
                "publicationAuthorized":False,"distributionAuthorized":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    require(not args.output.exists() and not args.output.is_symlink(),
            "do not overwrite previous original audit evidence")
    report=execute()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":report["status"],
                      "originalPGSigstoreVerified":report["verifiedPgCount"],
                      "eventCanonicalSha256":report["eventCanonicalSha256"],
                      "publicationAuthorized":False,
                      "distributionAuthorized":False},sort_keys=True))


if __name__=="__main__":
    try:
        main()
    except (Denied,OSError,KeyError,TypeError,ValueError) as exc:
        raise SystemExit("DENY: "+str(exc)) from exc
