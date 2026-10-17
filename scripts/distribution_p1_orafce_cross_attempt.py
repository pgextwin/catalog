#!/usr/bin/env python3
"""Issue #112 exact orafce PG14-17 cross-attempt proof; no failed-Run waiver.

Only the four original signed ZIPs in the immutable observed record qualify.
Original attempt 1 explicitly FAILED (PG18); these PG jobs SUCCEEDED in
attempt 1. Original publication and PG18 succeeded in attempt 2. This
contract verifies their exact artifact-byte continuity and *separately*
genuine dual Sigstore for each original PG attempt-1 build. Other failed
runs, particularly plpgsql_check, cannot enter this profile.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from zipfile import ZipFile

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_historical_fleet import (
    LOG_BLOBS, blob_sha, fixed_originals, historical_upstream,
)
from distribution_release_audit_p1 import gh_read
from distribution_release_verify_p1 import (
    PROVENANCE, SPDX, sha, verify_sigstore_offline,
)

ROOT = Path(__file__).resolve().parents[1]
OBSERVED = ROOT / "evidence/p1/orafce-cross-attempt-observed-v1.json"
PUB = ROOT / "evidence/p1/orafce-attempt2-original-publication-log-v1.json"
ARCHIVE = ROOT / "evidence/p1/historical-original-jobs/orafce.json"
OBSERVED_BLOB = "__OBSERVED_BLOB__"
PUBLISH_BLOB = "591f05c75cf0a5aacbedcc2cd339822080e4ad5f"
EXPECTED_PG = {14, 15, 16, 17}
RUN = 38062983035
SHA = "9f10b9039abe8c909df1ed17133481f4d64da1e4"
PUBLISH = 114251123808


def _read_pinned(path, expected_blob):
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size < 1024 * 1024,
            "BLOCKED: original cross-attempt evidence missing")
    raw = path.read_bytes()
    require(blob_sha(raw) == expected_blob,
            "BLOCKED: original cross-attempt evidence Git Blob changed")
    return strict_json(raw)


def _gh_json(path):
    require(re.fullmatch(
        r"repos/pgextwin/orafce/actions/runs/38062983035/attempts/[12](?:/jobs\?per_page=100)?",
        path), "unsafe cross-attempt GET operation")
    try:
        p = subprocess.run(("gh", "api", path), capture_output=True,
                           timeout=90, env={**os.environ,
                                            "GH_PROMPT_DISABLED": "1",
                                            "GH_NO_UPDATE_NOTIFIER": "1"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Denied("BLOCKED: original exact-attempt GET unavailable") from exc
    require(p.returncode == 0 and 0 < len(p.stdout) <= 8 * 1024 * 1024,
            "BLOCKED: original exact-attempt API unavailable")
    return strict_json(p.stdout)


def _authentic_attempts(obs, major):
    runs = [_gh_json(f"repos/pgextwin/orafce/actions/runs/{RUN}/attempts/{n}")
            for n in (1, 2)]
    for n, run in enumerate(runs, 1):
        require(type(run) is dict and run.get("id") == RUN
                and run.get("run_attempt") == n and
                run.get("head_sha") == SHA and run.get("event") == "push"
                and run.get("path") == ".github/workflows/windows.yml"
                and run.get("status") == "completed"
                and (run.get("repository") or {}).get("id") == 1413246504,
                "original orafce Run attempt identity changed")
    require(runs[0]["conclusion"] == "failure" and
            runs[1]["conclusion"] == "success",
            "attempt 1 failed and attempt 2 succeeded contract changed")
    jobs = [_gh_json(f"repos/pgextwin/orafce/actions/runs/{RUN}/attempts/{n}/jobs?per_page=100")
            for n in (1, 2)]
    for i, result in enumerate(jobs, 1):
        rows = result.get("jobs") if type(result) is dict else None
        require(type(rows) is list and len(rows) == result.get("total_count")
                and len(rows) <= 100
                and len({j.get("id") for j in rows}) == len(rows),
                "original exact-attempt Jobs partial or duplicated")
    target = next(x for x in obs["rows"] if x["pgMajor"] == int(major))
    original = [j for j in jobs[0]["jobs"]
                if j.get("id") == target["buildJobId"]]
    publishes = [j for j in jobs[1]["jobs"] if j.get("id") == PUBLISH]
    require(len(original) == 1 and len(publishes) == 1
            and original[0].get("name") ==
                f"release_build / PostgreSQL {major} / Windows x64"
            and original[0].get("conclusion") == "success"
            and original[0].get("run_attempt") == 1
            and original[0].get("head_sha") == SHA
            and publishes[0].get("name") == "release / Publish GitHub Release"
            and publishes[0].get("conclusion") == "success"
            and publishes[0].get("run_attempt") == 2
            and publishes[0].get("head_sha") == SHA,
            "failed/replayed original cross-attempt PG Job or publication")
    return {"originalBuildJobId": target["buildJobId"],
            "originalBuildAttempt": 1, "finalPublishJobId": PUBLISH,
            "finalPublicationAttempt": 2,
            "originalRunAttempt1Conclusion": "failure",
            "finalRunAttempt2Conclusion": "success"}


def _log_continuity(obs, major, source):
    pub = _read_pinned(PUB, PUBLISH_BLOB)
    archive = _read_pinned(ARCHIVE, LOG_BLOBS["orafce"])
    require(pub["schema"] == "pgextwin-original-orafce-publication-log/v1"
            and pub["runId"] == RUN and pub["runAttempt"] == 2
            and pub["publishJobId"] == PUBLISH
            and archive["originalRunId"] == RUN
            and archive["packagingSha"] == SHA,
            "wrong immutable cross-attempt publication archive")
    assert_major = next(x for x in obs["rows"] if x["pgMajor"] == int(major))
    logs = [x for x in archive["logs"] if x.get("pg") == str(major)]
    require(len(logs) == 1 and logs[0]["id"] == assert_major["buildJobId"]
            and logs[0]["attempt"] == 1,
            "original archived PG Job attempt is not 1")
    raw = logs[0]["content"]
    text = pub["fullText"]
    require(type(raw) is str and type(text) is str
            and len(raw) <= 200000 and len(text) <= 100000
            and "repository: " + source["upstreamRepository"] in raw
            and source["upstreamCommit"] in raw
            and ("ref: " + source["upstreamCommit"] in raw or
                 "ref: " + source["upstreamRef"] in raw),
            "original build Job source checkout not authenticated")
    zipped = assert_major["originalZipSha256"]
    uploaded = assert_major["uploadedArtifactArchiveSha256"]
    require(raw.count("Attestation created for " +
                      assert_major["originalZipName"] + "@sha256:" + zipped) == 2
            and ("SHA256 digest of uploaded artifact is " + uploaded) in raw
            and ("SHA256 digest of downloaded artifact is " + uploaded) in text
            and text.count("SHA256 digest of downloaded artifact is ") == 5
            and "Total of 5 artifact(s) downloaded" in text
            and "gh release create" in text,
            "original signed ZIP/authenticated upload/publication continuity failed")
    return {"originalCheckoutLogSha256": hashlib.sha256(raw.encode()).hexdigest(),
            "publisherOriginalLogGitBlob": PUBLISH_BLOB,
            "originalArtifactTransferSha256": uploaded}


def probe_original_cross_attempt(*, name, major, pin, release, config, row,
                                 folder, hashes, trusted_root, root_sha, cache):
    """Success only for fully cryptographically authenticated cross-attempt row.

    Caller MUST still decide formal admission separately in versioned v5.
    """
    major = str(major)
    require(name == "orafce" and int(major) in EXPECTED_PG
            and pin["runId"] == RUN and pin["runAttempt"] == 2
            and pin["releaseId"] == release["id"] == 409043426
            and pin["packagingSha"] == release["target_commitish"] == SHA,
            "cross-attempt verification only for original orafce PG14-17")
    obs = _read_pinned(OBSERVED, OBSERVED_BLOB)
    require(obs["schema"] == "pgextwin-p1-orafce-cross-attempt-observation/v1"
            and obs["decision"] == "EVIDENCE_OBSERVED_NOT_SIGNATURE_VERIFIED"
            and obs["packagingSha"] == SHA and obs["runId"] == RUN
            and obs["attempt1"] == {"conclusion":"failure", "failedBuildMajor":18,
                                    "publishSucceeded":False}
            and obs["attempt2"]["conclusion"] == "success"
            and len(obs["rows"]) == 4 and
            {r["pgMajor"] for r in obs["rows"]} == EXPECTED_PG,
            "wrong signed-batch-only historical cross-attempt evidence")
    target = next(x for x in obs["rows"] if x["pgMajor"] == int(major))
    require(row["asset"] == target["originalZipName"]
            and hashes[row["asset"]] == target["originalZipSha256"],
            "actual public Release original ZIP digest/PG identity does not match")
    origin = fixed_originals(name, pin, release, config)
    zp = folder / row["asset"]
    with ZipFile(zp) as z:
        pkg = strict_json(z.read("PACKAGE-INFO.json").decode("utf-8-sig"))
    wf = pkg.get("workflowRun") or {}
    source_info = pkg.get("source") or {}
    infra = pkg.get("buildInfrastructure") or {}
    require(wf.get("id") == RUN and wf.get("attempt") == 1
            and wf.get("event") == "push" and wf.get("ref") == pin["sourceRef"]
            and source_info.get("packagingCommit") == SHA
            and infra.get("commit") == pin["signerSha"]
            and infra.get("repository") == "pgextwin/build",
            "original ZIP was not cryptographically built in exact attempt 1")
    jobs = _authentic_attempts(obs, major)
    upstream = historical_upstream(name, major, config, pkg, cache=cache)
    continuity = _log_continuity(obs, major, upstream)
    require(trusted_root is not None, "BLOCKED: official TUF root unavailable")
    sigdir = folder / ("orafce-cross-attempt-" + major)
    sigdir.mkdir(exist_ok=False)
    gh_read("attestation", "download", str(zp.resolve()), "--repo",
            "pgextwin/orafce", cwd=sigdir)
    bundle = next((p for p in (
        sigdir / ("sha256:" + target["originalZipSha256"] + ".jsonl"),
        sigdir / ("sha256-" + target["originalZipSha256"] + ".jsonl"))
        if p.is_file() and not p.is_symlink()), None)
    require(bundle is not None, "original attempt-1 Sigstore bundle missing")
    bundle_sha = sha(bundle)
    spdx = strict_json((folder / row["evidence"]["sbom"]["asset"]).read_bytes())
    crypt = verify_sigstore_offline(
        zp, spdx, repo="pgextwin/orafce", repo_id=pin["repositoryId"],
        packaging_sha=SHA, signer_sha=pin["signerSha"], run_id=RUN,
        attempt=1, root_path=trusted_root, root_sha=root_sha,
        bundles={PROVENANCE: (bundle,bundle_sha), SPDX: (bundle,bundle_sha)},
        source_ref=pin["sourceRef"], build_trigger="push", workflow_path="windows.yml")
    require(crypt["signatureVerified"] is True, "original attempted PG dual Sigstore invalid")
    return {"decision":"PASS_CANDIDATE", "integrityVerified":True,
            "signatureVerified":True, "verificationProfile":"strict-orafce-cross-attempt/v1",
            "runId":RUN, "runAttempt":1,
            "signatureProof":{"bundleSha256":bundle_sha,
                              "signerSha":pin["signerSha"], **origin, **jobs,
                              **upstream, **continuity},
            "publicationAuthorized":False, "distributionAuthorized":False}
