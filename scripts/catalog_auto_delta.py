#!/usr/bin/env python3
"""Fail-closed discovery for the existing independently signed Catalog proposer.

This only emits candidate extension/tag pairs for the already deployed
sync-verified-release.yml verifier. A drift record is NEVER verification of
signed assets, an automatic Release permission or a PR merge authorization.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.request import Request, build_opener, HTTPRedirectHandler

from verified_release_record import INTAKE_ALLOWED, FIRST_RELEASE, FIRST_RELEASE_SOURCES

TAG = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")
DATE = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class Denied(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Denied(reason)


def discover(index, records, published, open_prs, *, manual=None):
    """Pure discovery; ALL returned rows still need full signed verification."""
    require(type(index) is dict and type(index.get("schemaVersion")) is int
            and index["schemaVersion"] == 2
            and isinstance(index.get("extensions"), list)
            and all(type(n) is str for n in index["extensions"])
            and len(index["extensions"]) == len(set(index["extensions"])),
            "invalid or duplicate Catalog distribution roster")
    indexed = set(index["extensions"])
    authorized = set(INTAKE_ALLOWED)
    first_release = set(FIRST_RELEASE) & set(FIRST_RELEASE_SOURCES)
    require(bool(indexed) and indexed.issubset(authorized)
            and (authorized - indexed).issubset(first_release)
            and set(FIRST_RELEASE).issubset(set(FIRST_RELEASE_SOURCES)),
            "missing established Catalog record or unapproved first-Release identity")
    require(type(open_prs) is list and len(open_prs) < 100, "incomplete PR inventory")
    existing = set()
    for pr in open_prs:
        require(type(pr) is dict and isinstance(pr.get("headRef"), str)
                and isinstance(pr.get("state"), str), "malformed open PR record")
        if pr["state"] == "open":
            existing.add(pr["headRef"])
    if manual is not None:
        require(type(manual) is tuple and len(manual) == 2, "invalid manual request")
        name, tag = manual
        require(name in INTAKE_ALLOWED and type(tag) is str and TAG.fullmatch(tag),
                "manual target outside signed Catalog verifier allowlist")
        return {"include": [{"extension": name, "release_tag": tag}]}
    require(type(records) is dict and set(records) == indexed,
            "missing or unexpected existing Catalog records")
    require(type(published) is dict and set(published) == set(INTAKE_ALLOWED),
            "incomplete per-repository public Release inventory")
    result = []
    for name in sorted(INTAKE_ALLOWED):
        is_initial = name not in indexed
        if not is_initial:
            record = records[name]
            require(type(record) is dict and record.get("name") == name
                    and type(record.get("schemaVersion")) is int
                    and record["schemaVersion"] == 2
                    and record.get("repository") == "pgextwin/" + name,
                    "invalid current Catalog record: " + name)
            current = record.get("latest")
            require(type(current) is dict and type(current.get("releaseTag")) is str
                    and TAG.fullmatch(current["releaseTag"])
                    and type(current.get("publishedAt")) is str
                    and DATE.fullmatch(current["publishedAt"]),
                    "missing or malformed current Catalog Release identity")
        collection = published[name]
        require(type(collection) is list and len(collection) < 100
                and (bool(collection) or is_initial),
                "empty/paginated existing public Release inventory: " + name)
        public = []
        ids = set()
        for r in collection:
            require(type(r) is dict and type(r.get("id")) is int
                    and r["id"] > 0 and r["id"] not in ids
                    and type(r.get("draft")) is bool
                    and type(r.get("prerelease")) is bool
                    and type(r.get("tag_name")) is str,
                    "invalid Release record: " + name)
            ids.add(r["id"])
            if r["draft"] or r["prerelease"] or not TAG.fullmatch(r["tag_name"]):
                continue
            require(type(r.get("published_at")) is str and DATE.fullmatch(r["published_at"]),
                    "invalid stable public Release timestamp")
            public.append(r)
        if is_initial and not public:
            # An explicitly registered future extension need not already have
            # a Release. Never fabricate a tag or a blank Catalog record.
            continue
        require(public, "no eligible public stable Releases: " + name)
        latest = max(public, key=lambda r: (r["published_at"], r["id"]))
        tag = latest["tag_name"]
        if not is_initial:
            if tag == current["releaseTag"]:
                continue
            require(latest["published_at"] > current["publishedAt"],
                    "would downgrade or replace newer Catalog record: " + name)
        if "auto-catalog/" + name + "-" + tag in existing:
            continue
        result.append({"extension": name, "release_tag": tag})
    return {"include": result}


class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class GithubReader:
    def __init__(self, token):
        require(type(token) is str and bool(token), "GitHub read token required")
        self.token = token
        self.open = build_opener(RejectRedirect()).open

    def get(self, relative):
        require(type(relative) is str and (
            relative == "repos/pgextwin/catalog/pulls?state=open&base=main&per_page=100"
            or re.fullmatch(r"repos/pgextwin/[a-z][a-z0-9_]*/releases\?per_page=100", relative)
        ), "non-allowlisted GitHub GET path")
        request = Request("https://api.github.com/" + relative, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "User-Agent": "pgextwin-catalog-signed-reconcile"
        }, method="GET")
        with self.open(request, timeout=25) as response:
            require(response.status == 200
                    and not re.search(r'\brel\s*=\s*"?next"?', response.headers.get("Link", ""), re.I),
                    "incomplete/paginated GitHub Release or PR inventory")
            body = response.read(2 * 1024 * 1024 + 1)
            require(len(body) <= 2 * 1024 * 1024, "GitHub response too large")
        return json.loads(body.decode("utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog-root", default=".")
    parser.add_argument("--manual-extension")
    parser.add_argument("--manual-tag")
    args = parser.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/catalog"
                and os.environ.get("GITHUB_REF") == "refs/heads/main",
                "Catalog reconciler only from protected main")
        event = os.environ.get("GITHUB_EVENT_NAME")
        require(event in ("schedule", "workflow_dispatch"), "unsupported event")
        root = Path(args.catalog_root)
        index = json.loads((root / "index.json").read_text("utf-8"))
        records = {name: json.loads((root / "extensions" / (name + ".json")).read_text("utf-8"))
                   for name in index["extensions"]}
        api = GithubReader(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
        prs = api.get("repos/pgextwin/catalog/pulls?state=open&base=main&per_page=100")
        pr_rows = [{"state": r["state"], "headRef": r["head"]["ref"]} for r in prs]
        manual = None
        if event == "workflow_dispatch":
            require(args.manual_extension is not None and args.manual_tag is not None,
                    "manual trigger requires explicit extension and tag")
            manual = (args.manual_extension, args.manual_tag)
        else:
            require(args.manual_extension is None and args.manual_tag is None,
                    "scheduled trigger must not accept user-provided tag")
        releases = {} if manual else {
            name: api.get("repos/pgextwin/" + name + "/releases?per_page=100")
            for name in sorted(INTAKE_ALLOWED)
        }
        matrix = discover(index, records, releases, pr_rows, manual=manual)
        output = json.dumps(matrix, separators=(",", ":"), sort_keys=True)
        enabled = "true" if matrix["include"] else "false"
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
                out.write("targets=" + output + "\n")
                out.write("has_changes=" + enabled + "\n")
        print("Catalog signed revalidation candidates:", len(matrix["include"]))
        for row in matrix["include"]:
            print(row["extension"], row["release_tag"], "INDEPENDENT_SIGNED_VERIFICATION_REQUIRED")
        return 0
    except (Denied, KeyError, TypeError, ValueError, OSError) as error:
        print("CATALOG DELTA DISCOVERY DENIED:", str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
