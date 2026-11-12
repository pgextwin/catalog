#!/usr/bin/env python3
"""PGroonga 4.1.0 original upstream producer-chain boundary; DENY-only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request

import issue112_pgroonga_detached_signature_review as prior

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc"
TAG = "a40db64f8e4761d3dc00b457faabf00d0613a711"
RUNS = {
    "windows": (37872644159, 1, ".github/workflows/windows.yml", "c1b2497d4f43e969214ff30ccbe846ebdc7c146c"),
    "release": (37872644104, 2, ".github/workflows/release.yml", "495623c715629761a978e22a83be9269a1b5c5f3"),
}
WINDOWS_JOBS = {"14": 113633984915, "15": 113633984767,
                "16": 113633984557, "17": 113633984752, "18": 113633984742}
ARTIFACTS = {
    "14": (11590129653, 53261546, "39e3a50fb8aa857e007f2af42f103824b0eb54c0091dd345db941851b05c3088"),
    "15": (11590989124, 53317133, "8cbd5a43aba3ebb4ec360709db6aa077925ce7a6109da33c7024f694e6074d38"),
    "16": (11590348972, 53205129, "552959c27733e0b1c789a426bb383da4acf04bb6fb42f13217bb3880d60a4c5e"),
    "17": (11591150953, 53294168, "0a32411389a3a81a48fffb520d1bab5963676df0a74493e38e3b4a79f35e1e84"),
    "18": (11590859682, 53278986, "fe6388d9928fda9f1d2a350e7dc6a30200ebd9f6c933e008f02315dced444c91"),
}
DENY = {"signedSourceToBinaryProvenance": False,
        "allThirdPartyRightsAndDependenciesVerified": False,
        "independentOwnerSignedAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False}


def require(ok, message):
    if not ok:
        raise ValueError("PGroonga producer-chain DENY: " + message)


def api(path):
    url = "https://api.github.com/repos/pgroonga/pgroonga/" + path
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "pgextwin-producer-boundary/1"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                timeout=30) as stream:
        require(stream.status == 200 and stream.geturl() == url,
                "unexpected GitHub API redirect")
        data = stream.read(800001)
    require(len(data) <= 800000, "unbounded REST metadata")
    return json.loads(data, object_pairs_hook=prior.unique)


def validate_tag(ref, tag):
    require(ref.get("ref") == "refs/tags/4.1.0" and
            ref.get("object", {}).get("type") == "tag" and
            ref["object"].get("sha") == TAG, "tag reference substitution")
    require(tag.get("sha") == TAG and tag.get("tag") == "4.1.0" and
            tag.get("object", {}).get("type") == "commit" and
            tag["object"].get("sha") == COMMIT, "tag target substitution")
    require(tag.get("verification", {}).get("verified") is False and
            tag["verification"].get("reason") == "unsigned",
            "tag-signing status altered")
    return {"tagObject": TAG, "sourceCommit": COMMIT, "tagSigned": False}


def validate_run(run, kind):
    run_id, attempt, path, _ = RUNS[kind]
    require(run.get("id") == run_id and run.get("run_attempt") == attempt and
            run.get("path") == path and run.get("head_branch") == "4.1.0" and
            run.get("head_sha") == COMMIT and run.get("event") == "push" and
            run.get("status") == "completed" and run.get("conclusion") == "success" and
            run.get("actor", {}).get("login") == "abetomo",
            "wrong " + kind + " original run/attempt/event/actor/SHA")
    return {"runId": run_id, "attempt": attempt, "head": COMMIT}


def validate_jobs(page, kind):
    rows = page.get("jobs")
    count = 6 if kind == "windows" else 4
    require(type(rows) is list and page.get("total_count") == count and
            len(rows) == count and len({j.get("id") for j in rows}) == count,
            "missing or duplicate upstream jobs")
    by_id = {j["id"]: j for j in rows}
    expected = WINDOWS_JOBS if kind == "windows" else {"GitHub": 113650372251}
    for pg, job_id in expected.items():
        j = by_id.get(job_id)
        title = "PostgreSQL " + pg if kind == "windows" else "GitHub"
        steps = ("Configure Groonga", "Package") if kind == "windows" else (
            "Download artifacts", "Publish")
        require(j is not None and j.get("name") == title and
                j.get("head_sha") == COMMIT and
                j.get("run_attempt") == RUNS[kind][1] and
                j.get("status") == "completed" and j.get("conclusion") == "success",
                "original job identity or conclusion mismatch")
        items = j.get("steps")
        require(type(items) is list and len({x.get("name") for x in items}) == len(items),
                "duplicate or missing job steps")
        by_name = {x["name"]: x for x in items}
        require(all(by_name.get(name, {}).get("conclusion") == "success" for name in steps),
                "original job required steps not successful")
    return sorted(expected.values())


def validate_artifacts(page):
    rows = page.get("artifacts")
    require(type(rows) is list and len(rows) == 6 and
            page.get("total_count") == 6 and
            len({r.get("id") for r in rows}) == 6 and
            len({r.get("name") for r in rows}) == 6,
            "incomplete or duplicate original Actions artifacts")
    by_name = {r["name"]: r for r in rows}
    result = []
    for pg, (aid, length, digest) in sorted(ARTIFACTS.items()):
        row = by_name.get("release-postgresql-" + pg + "-x64")
        require(row is not None and row.get("id") == aid and
                row.get("size_in_bytes") == length and
                row.get("digest") == "sha256:" + digest and
                row.get("expired") is False and
                row.get("workflow_run", {}).get("id") == RUNS["windows"][0],
                "wrong original Actions artifact PG" + pg)
        result.append({"pg": pg, "outerArtifactId": aid,
                       "outerArchiveBytes": length, "outerArchiveApiSha256": digest})
    return result


def validate_workflow(data, kind):
    _, _, path, sha = RUNS[kind]
    require(data.get("path") == path and data.get("sha") == sha and
            data.get("encoding") == "base64" and type(data.get("content")) is str,
            "untrusted immutable producer workflow path/blob")
    content = base64.b64decode(re.sub(r"\s+", "", data["content"]), validate=True)
    digest = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" +
                          content).hexdigest()
    require(digest == sha, "Git workflow blob byte identity mismatch")
    source = content.decode("utf-8")
    patterns = ("groonga-latest.zip", "Download Groonga", "actions/upload-artifact@v7") if kind == "windows" else (
        "gh run list", "--limit 1", "gh run download", "gh release create")
    require(all(part in source for part in patterns),
            "producer source input or Release selection changed")
    return {"path": path, "gitBlob": sha,
            "mutableUpstreamSourceOrRunSelectorObserved": True}


def audit():
    baseline = prior.strict_baseline(ROOT / "external/pgroonga-release-watch-baseline-v1.json")
    prior.validate_metadata(api("releases/407467158"), baseline)
    result = {"schemaVersion": "pgextwin-pgroonga-original-producer-boundary-deny-only/v1",
              "sourceTag": validate_tag(api("git/ref/tags/4.1.0"),
                                        api("git/tags/" + TAG)),
              "originalRuns": {}, "originalJobs": {}, "immutableSource": {}}
    for kind, (run_id, _, path, _) in RUNS.items():
        result["originalRuns"][kind] = validate_run(api("actions/runs/" + str(run_id)), kind)
        result["originalJobs"][kind] = validate_jobs(
            api("actions/runs/" + str(run_id) + "/jobs?per_page=100"), kind)
        result["immutableSource"][kind] = validate_workflow(
            api("contents/" + path + "?ref=" + COMMIT), kind)
    result["outerArtifactsMetadata"] = validate_artifacts(
        api("actions/runs/" + str(RUNS["windows"][0]) + "/artifacts?per_page=100"))
    result.update(originalDetachedZIPSignaturePreviouslyVerified=True,
                  historicalMutableGroongaInputSha256Known=False,
                  originalSourceInputToReleasedZIPAttested=False, **DENY)
    return result


if __name__ == "__main__":
    print(json.dumps(audit(), sort_keys=True))
    print("UPSTREAM_PRODUCER_METADATA=VERIFIED INPUT_SHA256=UNKNOWN "
          "SIGNED_BUILD_PROVENANCE=DENY PUBLIC_GET=DENY MIRROR=DENY "
          "RELEASE=DENY PUBLISH=DENY")
