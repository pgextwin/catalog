#!/usr/bin/env python3
"""Issue #112: original-byte historical windows.yml PUSH verifier (12 fixed releases).

This does NOT reuse pg_bigm PG14's identity exception, and does not replace
the genuine gh+TUF+SLSA/SPDX cryptographic verifier. All inputs must be
reconciled with original numeric-pinned Release bytes and GitHub GET.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote
from zipfile import ZipFile

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_release_verify_p1 import (
    PROVENANCE, SPDX, sha, verify_sigstore_offline,
)
from distribution_release_audit_p1 import api_json, pinned_content, gh_read

HEX40 = re.compile(r"[a-f0-9]{40}\Z")
REF = re.compile(r"refs/heads/release/[A-Za-z0-9_.-]+\Z")
UPSTREAM = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
UPSTREAM_REF = re.compile(r"[A-Za-z0-9_.-]+\Z")
PINNED_SOURCE_REGISTRY_BLOB = "c04a8c34688265cfd598fe99c399aa032321ed61"
OLD_SIGNERS = frozenset({
    "8246f4d3415a48b1ad4af13f421277057886b58f",
    "43993b864e59bd35870e15c410ac13c85def8531",
    "26be1eed57d8945e5e0a970d432074c530679b8f",
})


def blob_sha(raw):
    require(type(raw) is bytes and len(raw) <= 1024 * 1024, "unbounded Git blob")
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def pins_load(raw, policy):
    require(blob_sha(raw) == PINNED_SOURCE_REGISTRY_BLOB,
            "historical registry full Git Blob SHA changed")
    p = strict_json(raw)
    require(type(p) is dict and p.get("schema") ==
            "pgextwin-p1-historical-evidence-pins/v1"
            and p.get("catalogCommit") == policy["catalogCommitSha"]
            and p.get("historicalProfile") == "windows.yml/push/refs/heads/release/*"
            and type(p.get("items")) is list and len(p["items"]) == 12,
            "unsupported historical pin inventory")
    expected = set(policy["repoIds"]) - {"wal2json", "plpgsql_check"}
    require(set(x.get("name") for x in p["items"]) == expected,
            "missing/duplicate/unexpected historical repositories")
    out = {}
    for x in p["items"]:
        name = x["name"]
        require(x.get("repositoryId") == policy["repoIds"][name]
                and x.get("releaseId") == policy["releaseIds"][name]
                and all(type(x.get(k)) is str and HEX40.fullmatch(x[k]) for k in
                        ("packagingSha", "workflowBlob", "configBlob", "signerSha"))
                and x["signerSha"] in OLD_SIGNERS
                and type(x.get("runId")) is int and x["runId"] > 0
                and type(x.get("runAttempt")) is int and x["runAttempt"] in (1, 2)
                and type(x.get("sourceRef")) is str
                and REF.fullmatch(x["sourceRef"]),
                "unsupported source/signer/release/Run pin")
        out[name] = x
    return out


def fixed_originals(name, pin, release, config):
    require(release["id"] == pin["releaseId"]
            and release["target_commitish"] == pin["packagingSha"]
            and pin["sourceRef"] == "refs/heads/release/" + release["tag_name"],
            "historical original Release is not pinned to source")
    workflow = pinned_content(name, ".github/workflows/windows.yml",
                              pin["packagingSha"])
    cfg = pinned_content(name, "config/extension.json", pin["packagingSha"])
    require(blob_sha(workflow) == pin["workflowBlob"]
            and blob_sha(cfg) == pin["configBlob"],
            "historical immutable Git blob mismatch")
    require(strict_json(cfg) == config, "historical origin config mismatch")
    w = workflow.decode("utf-8")
    signer = ("pgextwin/build/.github/workflows/build-extension-attested.yml@" +
              pin["signerSha"])
    require(w.count("uses: " + signer) == 1
            and "push:" in w and "release/**" in w
            and "release_build:" in w and "release:" in w,
            "historical workflow does not pin exact builder/ref/push jobs")
    return {"workflowBlob": pin["workflowBlob"], "configBlob": pin["configBlob"]}


def historical_run(name, pin, pkg):
    wf = pkg.get("workflowRun") if type(pkg) is dict else None
    src = pkg.get("source") if type(pkg) is dict else None
    infra = pkg.get("buildInfrastructure") if type(pkg) is dict else None
    require(type(wf) is dict and type(src) is dict and type(infra) is dict
            and wf.get("id") == pin["runId"]
            and wf.get("attempt") == pin["runAttempt"]
            and wf.get("event") == "push" and wf.get("ref") == pin["sourceRef"]
            and wf.get("url") ==
                "https://github.com/pgextwin/" + name + "/actions/runs/" +
                str(pin["runId"])
            and src.get("packagingRepository") == "pgextwin/" + name
            and src.get("packagingCommit") == pin["packagingSha"]
            and infra.get("repository") == "pgextwin/build"
            and infra.get("workflow") == ".github/workflows/build-extension-attested.yml"
            and infra.get("commit") == pin["signerSha"],
            "historical PACKAGE-INFO source/event/ref/Run/signer mismatch")
    run = api_json(name + "/actions/runs/" + str(pin["runId"]))
    require(run.get("id") == pin["runId"]
            and run.get("run_attempt") == pin["runAttempt"]
            and run.get("event") == "push"
            and run.get("path") == ".github/workflows/windows.yml"
            and run.get("head_branch") == pin["sourceRef"][11:]
            and run.get("head_sha") == pin["packagingSha"]
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and (run.get("repository") or {}).get("id") == pin["repositoryId"]
            and (run.get("repository") or {}).get("full_name") ==
                "pgextwin/" + name,
            "original historical Run/attempt is not successful or immutable")
    return run


def historical_jobs(name, major, pin):
    # GET exactly the original Run's jobs; reject incomplete pagination, cross-attempt
    # replay, job-name aliases, failed/skipped builds, and ambiguous publications.
    api_path = (f"repos/pgextwin/{name}/actions/runs/{pin['runId']}"
                "/jobs?per_page=100")
    try:
        p = subprocess.run(("gh", "api", api_path), capture_output=True,
                           timeout=90, env={**os.environ, "GH_PROMPT_DISABLED": "1",
                                            "GH_NO_UPDATE_NOTIFIER": "1"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Denied("original historical jobs GET unavailable") from exc
    require(p.returncode == 0 and 0 < len(p.stdout) <= 8*1024*1024,
            "historical jobs GET incomplete")
    result = strict_json(p.stdout)
    jobs = result.get("jobs")
    require(type(jobs) is list and len(jobs) == result.get("total_count")
            and 0 < len(jobs) <= 100
            and len({j.get("id") for j in jobs if type(j) is dict}) == len(jobs),
            "historical jobs missing/duplicated/paginated")
    expected = ("release_build / PostgreSQL " + major + " / Windows x64",
                "release / Publish GitHub Release")
    ids = []
    for n in expected:
        candidates = [j for j in jobs if j.get("name") == n]
        require(len(candidates) == 1
                and candidates[0].get("conclusion") == "success"
                and candidates[0].get("run_attempt") == pin["runAttempt"]
                and candidates[0].get("head_sha") == pin["packagingSha"],
                "historical original named PG/publication job failed or changed")
        ids.append(candidates[0]["id"])
    return {"buildJobId": ids[0], "publicationJobId": ids[1]}


def historical_upstream(name, major, config, pkg, *, cache):
    """Compare original PACKAGE-INFO with pinned original config AND upstream tag.

    A PACKAGE-INFO SHA assertion by itself is never accepted as independent
    upstream evidence. Ambiguous upstream refs and unavailable GitHub GET DENY.
    """
    upstream = config.get("upstream") or {}
    actual = pkg.get("upstream") if type(pkg) is dict else None
    require(type(upstream) is dict and type(actual) is dict,
            "missing upstream provenance")
    per = upstream.get("perPostgresql")
    expected = per.get(major) if type(per) is dict else upstream
    require(type(expected) is dict, "missing PG-specific upstream ref")
    repo, ref, version = upstream.get("repository"), expected.get("ref"), expected.get("version")
    require(type(repo) is str and UPSTREAM.fullmatch(repo)
            and type(ref) is str and UPSTREAM_REF.fullmatch(ref)
            and type(version) is str and version
            and actual.get("repository") == repo and actual.get("ref") == ref
            and actual.get("version") == version,
            "original config/package upstream ref/version mismatch")
    commit = actual.get("commit")
    require(type(commit) is str and HEX40.fullmatch(commit)
            and (expected.get("commit") is None or expected["commit"] == commit),
            "unsigned/upstream full commit absent or mismatched")
    key = (repo, ref)
    if key not in cache:
        # Independently resolve immutable upstream ref using genuine pinned gh
        # executable, HTTPS GitHub API GET-only, never shell or arbitrary host.
        path = "repos/" + repo + "/commits/" + quote(ref, safe="")
        try:
            p = subprocess.run(("gh", "api", path), capture_output=True,
                               timeout=90, env={**os.environ, "GH_PROMPT_DISABLED": "1",
                                                "GH_NO_UPDATE_NOTIFIER": "1"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Denied("upstream original ref GET unavailable") from exc
        require(p.returncode == 0 and 0 < len(p.stdout) < 8*1024*1024,
                "independent upstream ref GET failed")
        resolved = strict_json(p.stdout)
        require(type(resolved) is dict and type(resolved.get("sha")) is str
                and HEX40.fullmatch(resolved["sha"]), "invalid upstream commit")
        cache[key] = resolved["sha"]
    require(cache[key] == commit, "original independent upstream SHA mismatch")
    return {"upstreamRepository": repo, "upstreamRef": ref,
            "upstreamCommit": commit}


def verify_historical_row(*, name, major, pin, release, config, row,
                          folder, assets, hashes, trusted_root, root_sha, cache):
    # This function is only called after original Release 16-asset SHA256,
    # 15 checksum, all ZIP CRC and SPDX/Grype structure checks passed.
    fixed = fixed_originals(name, pin, release, config)
    zp = folder / row["asset"]
    with ZipFile(zp) as archive:
        pkg = strict_json(archive.read("PACKAGE-INFO.json").decode("utf-8-sig"))
    history = historical_run(name, pin, pkg)
    jobs = historical_jobs(name, major, pin)
    source = historical_upstream(name, major, config, pkg, cache=cache)
    spdx = strict_json((folder / row["evidence"]["sbom"]["asset"]).read_bytes())
    require(trusted_root is not None, "BLOCKED: authenticated TUF root unavailable")
    attestdir = folder / ("historical-attest-" + major)
    attestdir.mkdir()
    gh_read("attestation", "download", str(zp.resolve()),
            "--repo", "pgextwin/" + name, cwd=attestdir)
    candidates = [attestdir / ("sha256:" + hashes[row["asset"]] + ".jsonl"),
                  attestdir / ("sha256-" + hashes[row["asset"]] + ".jsonl")]
    bundle = next((x for x in candidates if x.is_file() and not x.is_symlink()), None)
    require(bundle is not None, "original historical Sigstore JSONL unavailable")
    bundle_hash = sha(bundle)
    proof = verify_sigstore_offline(
        zp, spdx, repo="pgextwin/" + name, repo_id=pin["repositoryId"],
        packaging_sha=pin["packagingSha"], signer_sha=pin["signerSha"],
        run_id=pin["runId"], attempt=pin["runAttempt"],
        root_path=trusted_root, root_sha=root_sha,
        bundles={PROVENANCE: (bundle, bundle_hash),
                 SPDX: (bundle, bundle_hash)},
        source_ref=pin["sourceRef"], build_trigger="push",
        workflow_path="windows.yml")
    require(proof["signatureVerified"] is True, "real historical dual Sigstore failed")
    return {"decision": "PASS_CANDIDATE", "integrityVerified": True,
            "signatureVerified": True, "runId": pin["runId"],
            "runAttempt": pin["runAttempt"],
            "signatureProof": {"bundleSha256": bundle_hash,
                               "signerSha": pin["signerSha"], **jobs,
                               **source, **fixed},
            "publicationAuthorized": False, "distributionAuthorized": False}
