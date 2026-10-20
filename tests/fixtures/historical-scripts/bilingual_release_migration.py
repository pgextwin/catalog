#!/usr/bin/env python3
"""Safely retrofit public GitHub Release *bodies* only, from protected main.

This script cannot create, delete, re-tag, upload, or modify Release assets.
All release identities, original body text, tag SHA, publication state and
exact asset metadata are independently pinned before any PATCH is attempted.
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

SCHEMA = "pgextwin-historical-bilingual-notes/v1"
BASE = "https://api.github.com/repos/"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^[A-Za-z0-9._-]+$")

def normalized(text):
    return text.replace("\r\n", "\n").strip()

def load_manifest(path):
    value = json.loads(Path(path).read_text("utf-8"))
    assert value["schemaVersion"] == SCHEMA
    repo = value["repository"]
    assert re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", repo)
    rows = value["releases"]
    assert rows and len(rows) == len({x["id"] for x in rows})
    assert len(rows) == len({x["tag"] for x in rows})
    for row in rows:
        assert isinstance(row["id"], int) and row["id"] > 0
        assert TAG.fullmatch(row["tag"]) and SHA40.fullmatch(row["tagSha"])
        assert row["publishedAt"] and row["assets"]
        assert row["oldBody"] != row["newBody"]
        body = normalized(row["newBody"])
        assert body.startswith("# ") and "## English" in body and "## 日本語" in body
        assert 0 < body.index("## English") < body.index("## 日本語")
        assert body.count("## English") == body.count("## 日本語") == 1
        old = normalized(row["oldBody"])
        original_lines = [line.strip() for line in old.splitlines()
                          if line.strip() and not line.startswith("# ")]
        assert all(line in body for line in original_lines), "Original release lines must all be preserved"
        if repo == "pgextwin/catalog":
            assert "INTEGRITY_ONLY" in body or row["tag"].startswith("cli-v0.1.")
        else:
            assert "SHA256SUMS" in body, "Release evidence must be disclosed"
        names = [x["name"] for x in row["assets"]]
        assert len(names) == len(set(names))
        for item in row["assets"]:
            assert type(item["id"]) is int and item["id"] > 0
            assert type(item["size"]) is int and item["size"] >= 0
            assert re.fullmatch(r"[A-Za-z0-9._-]+", item["name"])
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"])
    return value

def request(repo, route, method="GET", body=None):
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("A scoped GitHub token is required for live verification")
    assert route.startswith("/") and ".." not in route and "?" not in route
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(BASE + repo + route, data=data, method=method,
        headers={"Accept":"application/vnd.github+json",
                 "Authorization":"Bearer " + token,
                 "X-GitHub-Api-Version":"2022-11-28",
                 "User-Agent":"pgextwin-historical-release-body-only/1",
                 **({"Content-Type":"application/json"} if data is not None else {})})
    with urllib.request.urlopen(req, timeout=30) as res:
        if res.status not in (200,):
            raise ValueError("Unexpected GitHub HTTP status")
        payload = res.read(3_000_000 + 1)
        if not payload or len(payload) > 3_000_000:
            raise ValueError("Unexpected GitHub metadata size")
        return json.loads(payload)

def assets(release):
    return sorted([{"id":v["id"],"name":v["name"],"size":v["size"],"digest":v["digest"]}
                   for v in release["assets"]], key=lambda v:v["name"])

def validate_live(repo, row, release, tag):
    assert release["id"] == row["id"] and release["tag_name"] == row["tag"]
    assert release["draft"] is False and release["published_at"] == row["publishedAt"]
    assert release["prerelease"] is row["prerelease"]
    assert tag["ref"] == "refs/tags/" + row["tag"]
    assert tag["object"]["type"] == "commit" and tag["object"]["sha"] == row["tagSha"]
    assert assets(release) == sorted(row["assets"], key=lambda x:x["name"]), "Release assets modified"
    actual = normalized(release.get("body") or "")
    assert actual in (normalized(row["oldBody"]), normalized(row["newBody"])), "Unexpected Release body drift"
    return actual == normalized(row["newBody"])

def run(path, mode):
    manifest = load_manifest(path)
    repo = manifest["repository"]
    print(f"BILINGUAL_RELEASE_MANIFEST=PASS REPOSITORY={repo} RELEASES={len(manifest['releases'])}")
    if mode == "plan":
        return
    main = request(repo, "/branches/main")
    assert main.get("protected") is True
    latest_before = None
    if repo == "pgextwin/catalog":
        latest_before = request(repo, "/releases/latest")
        assert latest_before["tag_name"].startswith("catalog-feed-"), "Signed feed latest pointer lost"
    pending = []
    # Entire batch must pass GET-only preflight before the first write.
    for row in manifest["releases"]:
        rel = request(repo, "/releases/" + str(row["id"]))
        tag = request(repo, "/git/ref/tags/" + row["tag"])
        already = validate_live(repo, row, rel, tag)
        pending.append((row, already))
    print(f"BILINGUAL_RELEASE_GET_PREFLIGHT=PASS REPOSITORY={repo} TOTAL={len(pending)}")
    if mode == "audit":
        return
    assert mode == "apply"
    for row, done in pending:
        if not done:
            before = request(repo, "/releases/" + str(row["id"]))
            tag = request(repo, "/git/ref/tags/" + row["tag"])
            validate_live(repo,row,before,tag)
            assert normalized(before["body"]) == normalized(row["oldBody"])
            request(repo, "/releases/" + str(row["id"]), "PATCH", {"body":row["newBody"]})
        after = request(repo, "/releases/" + str(row["id"]))
        tag = request(repo, "/git/ref/tags/" + row["tag"])
        assert validate_live(repo,row,after,tag), "Body update was not confirmed"
        print(f"BILINGUAL_RELEASE_BODY_ONLY=PASS {row['tag']} ID={row['id']} ASSETS={len(row['assets'])}")
    if latest_before:
        latest_after = request(repo, "/releases/latest")
        assert latest_after["tag_name"].startswith("catalog-feed-"), "Catalog latest changed to a CLI"
        print("BILINGUAL_CATALOG_STABLE_FEED_POINTER=PASS " + latest_after["tag_name"])
    assert request(repo, "/branches/main")["commit"]["sha"] == main["commit"]["sha"], "Main moved during audit"
    print(f"BILINGUAL_RELEASE_MIGRATION=PASS REPOSITORY={repo} TOTAL={len(pending)}")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--mode", choices=("plan","audit","apply"), required=True)
    args=parser.parse_args()
    run(args.manifest,args.mode)

if __name__ == "__main__":
    main()
