#!/usr/bin/env python3
"""Protected-main request -> existing public signed-Release verifier, no writes.

This never authorizes a Release, mints a token, proposes/merges a PR or changes
Catalog main. Normal Chat retrieves the verified record artifact and creates
the normal protected Catalog PR. No Workflow Dispatch or App is required.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import re

from catalog_drift_live_readonly import GitHubReadOnly, blob_sha, unique_json_pairs
from verified_release_record import INTAKE_ALLOWED, Denied, require
from verify_signed_fleet_release import generate

REPO = "pgextwin/catalog"
PREFIX = ".github/catalog-release-requests/"
WORKFLOW = ".github/workflows/catalog-chat-request.yml"
SHA = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*\Z")
FIELDS = frozenset({"schemaVersion", "type", "extension", "releaseTag", "releaseId",
                    "catalogBaseSha", "operatorLogin", "confirmCatalog"})


class RequestReader(GitHubReadOnly):
    @staticmethod
    def allowlisted(repo, path):
        require(type(path) is str and len(path) < 400, "invalid request read path")
        patterns = (r"branches/main", r"actions/runs/[1-9][0-9]*",
                    r"commits/[0-9a-f]{40}(?:/pulls\?per_page=100|/check-runs\?per_page=100)?",
                    r"pulls/[1-9][0-9]*(?:/files\?per_page=100)?",
                    r"contents/\.github/catalog-release-requests/[a-z][a-z0-9_]*-v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*\.json\?ref=[0-9a-f]{40}")
        if repo == REPO and any(re.fullmatch(p, path) for p in patterns):
            return
        if repo in {"pgextwin/"+n for n in INTAKE_ALLOWED} and re.fullmatch(r"releases/tags/v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*", path):
            return
        raise Denied("not a Catalog request GET endpoint")


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "invalid Catalog request size")
    r = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json_pairs)
    require(type(r) is dict and set(r) == FIELDS, "unknown/missing Catalog request key")
    require(type(r["schemaVersion"]) is int and r["schemaVersion"] == 1
            and r["type"] == "pgextwin-public-release-catalog-verification"
            and r["confirmCatalog"] == "VERIFY_PUBLIC_RELEASE", "not a Catalog verification request")
    require(r["extension"] in INTAKE_ALLOWED and type(r["releaseTag"]) is str
            and TAG.fullmatch(r["releaseTag"]), "unknown extension or invalid tag")
    require(type(r["releaseId"]) is int and r["releaseId"] > 0
            and type(r["catalogBaseSha"]) is str and SHA.fullmatch(r["catalogBaseSha"])
            and r["operatorLogin"] == "ShutenOishi", "invalid Release/main/operator identity")
    return r


def human(value):
    return type(value) is dict and value.get("type") == "User" and value.get("login") == "ShutenOishi"


def release_identity(api, request):
    release = api.get("pgextwin/"+request["extension"], "releases/tags/"+request["releaseTag"])
    require(type(release) is dict and type(release.get("id")) is int
            and release["id"] == request["releaseId"] and release.get("tag_name") == request["releaseTag"]
            and release.get("draft") is False and release.get("prerelease") is False
            and bool(release.get("published_at")) and type(release.get("target_commitish")) is str
            and SHA.fullmatch(release["target_commitish"]), "public exact Release ID/target missing")
    assets = release.get("assets")
    require(type(assets) is list and all(type(a) is dict and type(a.get("id")) is int for a in assets),
            "public asset identities missing")
    require(len({a["id"] for a in assets}) == len(assets), "duplicate asset identity")
    # Downloads themselves change download_count. Compare only stable public
    # identity, original digest/size and source/publication fields.
    return {k:release.get(k) for k in ("id","tag_name","target_commitish","published_at")} | {
        "assets":sorted([{k:a.get(k) for k in ("id","name","size","digest","created_at",
                            "updated_at","browser_download_url","state")} for a in assets],key=lambda a:a["id"])}


def resolve(api, env, event):
    require(env.get("GITHUB_REPOSITORY") == REPO and env.get("GITHUB_EVENT_NAME") == "push"
            and env.get("GITHUB_REF") == "refs/heads/main" and env.get("GITHUB_RUN_ATTEMPT") == "1",
            "trusted main push attempt required")
    sha = env.get("GITHUB_SHA", "")
    require(SHA.fullmatch(sha) and re.fullmatch(r"[1-9][0-9]*",env.get("GITHUB_RUN_ID", "")), "invalid runtime IDs")
    require(type(event) is dict and (event.get("repository") or {}).get("full_name") == REPO
            and event.get("after") == sha and event.get("ref") == "refs/heads/main"
            and human(event.get("sender")) and env.get("GITHUB_ACTOR") == "ShutenOishi"
            and event.get("created") is False and event.get("deleted") is False
            and type(event.get("commits")) is list and len(event["commits"]) == 1
            and event["commits"][0].get("id") == sha, "not one authenticated human main commit")
    run = api.get(REPO,"actions/runs/"+env["GITHUB_RUN_ID"])
    require(type(run.get("id")) is int and run["id"] == int(env["GITHUB_RUN_ID"])
            and run.get("repository",{}).get("full_name") == REPO and run.get("head_branch") == "main"
            and run.get("head_sha") == sha and run.get("event") == "push" and run.get("path") == WORKFLOW
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and human(run.get("actor")) and human(run.get("triggering_actor")), "run identity differs")
    branch = api.get(REPO,"branches/main")
    require(branch.get("protected") is True and branch.get("commit",{}).get("sha") == sha, "main stale/unprotected")
    commit = api.get(REPO,"commits/"+sha)
    require(commit.get("sha") == sha and len(commit.get("parents", [])) == 1
            and type(event.get("before")) is str and SHA.fullmatch(event["before"])
            and commit["parents"][0].get("sha") == event["before"]
            and commit.get("commit",{}).get("verification",{}).get("verified") is True
            and commit.get("commit",{}).get("verification",{}).get("reason") == "valid"
            and commit.get("committer",{}).get("login") == "web-flow", "signed squash identity missing")
    files = commit.get("files")
    require(type(files) is list, "commit files unavailable")
    selected = [f for f in files if str(f.get("filename", "")).startswith(PREFIX)
                or str(f.get("previous_filename", "")).startswith(PREFIX)]
    if not selected:
        require(api.get(REPO,"branches/main") == branch, "main raced")
        return None
    require(len(files) == len(selected) == 1 and selected[0].get("status") == "added", "one added request only")
    linked = api.get(REPO,"commits/"+sha+"/pulls?per_page=100")
    require(type(linked) is list and len(linked) == 1, "ambiguous request PR")
    pr = api.get(REPO,"pulls/"+str(linked[0]["number"]))
    require(pr.get("merged") is True and pr.get("state") == "closed" and pr.get("merge_commit_sha") == sha
            and human(pr.get("user")) and human(pr.get("merged_by"))
            and pr.get("head",{}).get("repo",{}).get("full_name") == REPO
            and pr.get("base",{}).get("repo",{}).get("full_name") == REPO
            and pr.get("base",{}).get("ref") == "main", "request human/repository merge missing")
    pr_files = api.get(REPO,"pulls/"+str(pr["number"])+"/files?per_page=100")
    require(type(pr_files) is list and pr.get("changed_files") == 1 and len(pr_files) == 1
            and [(f.get("filename"),f.get("sha"),f.get("status")) for f in pr_files] ==
                [(f.get("filename"),f.get("sha"),f.get("status")) for f in files], "request PR/commit blobs differ")
    head = pr.get("head",{}).get("sha", "")
    require(SHA.fullmatch(head), "invalid request head")
    checks = api.get(REPO,"commits/"+head+"/check-runs?per_page=100")
    require(type(checks.get("check_runs")) is list and checks.get("total_count") == len(checks["check_runs"]), "CI pagination")
    rules = branch.get("protection",{}).get("required_status_checks",{}).get("checks")
    require(rules == [{"context":"validate","app_id":15368}], "unknown required CI identity")
    passing = [c for c in checks["check_runs"] if c.get("name") == "validate" and c.get("app",{}).get("id") == 15368]
    require(len(passing) == 1 and passing[0].get("head_sha") == head
            and passing[0].get("status") == "completed" and passing[0].get("conclusion") == "success", "exact-head CI not successful")
    path = selected[0]["filename"]
    require(re.fullmatch(re.escape(PREFIX)+r"[a-z][a-z0-9_]*-v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*\.json",path), "invalid request pathname")
    obj = api.get(REPO,"contents/"+path+"?ref="+sha)
    require(obj.get("path") == path and obj.get("type") == "file" and obj.get("encoding") == "base64"
            and type(obj.get("size")) is int and 0 < obj["size"] <= 16384, "request blob missing")
    raw = base64.b64decode(obj["content"].replace("\n", ""),validate=True)
    require(len(raw) == obj["size"] and blob_sha(raw) == obj.get("sha") == selected[0].get("sha"), "blob mismatch")
    request = parse(raw)
    stem = request["extension"]+"-"+request["releaseTag"]
    require(path == PREFIX+stem+".json" and pr["head"].get("ref") == "catalog-verify/"+stem
            and request["catalogBaseSha"] == event["before"], "request target/base differs")
    release_identity(api,request)
    require(api.get(REPO,"branches/main") == branch, "main raced")
    return request


def verify(api, request, verifier=generate):
    before = release_identity(api,request)
    record = Path("extensions")/(request["extension"]+".json")
    mapped, audit = verifier(request["extension"],request["releaseTag"],record)
    require(audit.get("status") == "VERIFIED" and audit.get("repository") == "pgextwin/"+request["extension"]
            and audit.get("tag") == request["releaseTag"]
            and release_identity(api,request) == before,
            "signed verification or final immutable Release snapshot differs")
    return mapped, audit


def main():
    out = {"status":"DENY", "releasePublicationAuthorized":False,"catalogMainWriteAuthorized":False}
    try:
        api = RequestReader(os.environ["GH_TOKEN"])
        raw = Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes()
        require(len(raw) <= 2*1024*1024,"event too large")
        request = resolve(api,os.environ,json.loads(raw,object_pairs_hook=unique_json_pairs))
        if request is None:
            out["status"] = "NO_CATALOG_REQUEST"
        else:
            mapped, audit = verify(api,request)
            output = Path(os.environ["RUNNER_TEMP"])/"verified-catalog-chat-request"
            output.mkdir(exist_ok=False)
            (output/(request["extension"]+".json")).write_text(json.dumps(mapped,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
            out.update(status="VERIFIED_PUBLIC_RELEASE_RECORD_ONLY",extension=request["extension"],
                       releaseId=request["releaseId"],releaseTag=request["releaseTag"],audit=audit)
            (output/"audit.json").write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
            with open(os.environ["GITHUB_OUTPUT"],"a",encoding="utf-8") as stream:
                stream.write("verified=true\n")
        code = 0
    except Exception:
        code = 2
    print(json.dumps(out,sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
