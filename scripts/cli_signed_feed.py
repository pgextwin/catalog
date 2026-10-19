#!/usr/bin/env python3
"""Exact approved Catalog v2 -> read-only public ZIP feed builder.

The builder runs only on a protected-main, completed-success Validate workflow
and reads public Release metadata with workflow-scoped GitHub access.
It NEVER promotes a candidate, creates extension Releases, signs, publishes
or upgrades original ZIP Sigstore trust.
"""
import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

EXTENSION = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")
MAJORS = ("14", "15", "16", "17", "18")
LIMIT = 2_000_000
SCHEMA = "pgextwin-signed-catalog-zip-feed/v1"


def strict_object(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def source_bytes(root, relative):
    full = root / relative
    if full.is_symlink() or not full.is_file() or full.stat().st_size > LIMIT:
        raise ValueError("Missing, linked, or oversized source: " + relative)
    data = full.read_bytes()
    strict_object(data.decode("utf-8"))
    return data


def get_repo_json(repo, route, token=None):
    if not re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", repo):
        raise ValueError("Unexpected repository")
    if route and not re.fullmatch(r"/releases/tags/[A-Za-z0-9][A-Za-z0-9._-]*", route):
        raise ValueError("Unexpected Release route")
    url = "https://api.github.com/repos/" + repo + route
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "pgextwin-trusted-feed-generator/1",
        **({"Authorization": "Bearer " + token} if token else {}),
    })
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.url != url or response.status != 200:
            raise ValueError("Unexpected Github API redirect/status")
        data = response.read(LIMIT + 1)
    if not data or len(data) > LIMIT:
        raise ValueError("Invalid GitHub metadata size")
    return strict_object(data.decode("utf-8"))


def build_feed(root, commit, load):
    root = Path(root)
    if not SHA40.fullmatch(commit):
        raise ValueError("Full protected Catalog commit required")
    index_bytes = source_bytes(root, "index.json")
    index = strict_object(index_bytes.decode("utf-8"))
    names = index["extensions"]
    if index.get("schemaVersion") != 2 or not isinstance(names, list) or len(names) != 14 or (
        names != sorted(names) or len(names) != len(set(names)) or
        any(not isinstance(n, str) or not EXTENSION.fullmatch(n) for n in names)
    ):
        raise ValueError("Catalog extension inventory incomplete")
    source_hashes = {"index.json": hashlib.sha256(index_bytes).hexdigest()}
    records = []
    for name in names:
        location = f"extensions/{name}.json"
        raw = source_bytes(root, location)
        source_hashes[location] = hashlib.sha256(raw).hexdigest()
        data = strict_object(raw.decode("utf-8"))
        tag = data["latest"]["releaseTag"]
        repo = "pgextwin/" + name
        if (data["name"] != name or data["repository"] != repo or
            data["schemaVersion"] != 2 or data["architecture"] != "x64" or
            not isinstance(tag, str) or not ASSET.fullmatch(tag)):
            raise ValueError("Unsafe Catalog record identity")
        repo_data = load(repo, "")
        release = load(repo, "/releases/tags/" + tag)
        repository_id = repo_data.get("id")
        release_id = release.get("id")
        if (repo_data.get("full_name") != repo or
            type(repository_id) is not int or repository_id <= 0 or
            type(release_id) is not int or release_id <= 0 or
            release.get("tag_name") != tag or release.get("draft") is not False or
            not isinstance(release.get("published_at"), str)):
            raise ValueError("Public Release/repo identity mismatch")
        assets = {}
        used = set()
        for item in release["assets"]:
            asset = item["name"]
            ident = item["id"]
            if (not isinstance(asset, str) or not ASSET.fullmatch(asset) or
                type(ident) is not int or ident <= 0 or ident in used or
                asset in assets or item.get("state") != "uploaded" or
                item.get("browser_download_url") !=
                  f"https://github.com/{repo}/releases/download/{tag}/{asset}"):
                raise ValueError("Unsafe, duplicate, or moved Release asset")
            used.add(ident)
            assets[asset] = item
        if "SHA256SUMS.txt" not in assets:
            raise ValueError("Published checksum asset missing")
        packages = []
        for major in MAJORS:
            pg = data["postgresql"][major]
            if pg.get("available") is not True:
                raise ValueError("Incomplete Catalog PG14-18 availability")
            filename = pg["asset"]
            digest = pg["sha256"]
            url = f"https://github.com/{repo}/releases/download/{tag}/{filename}"
            if (not isinstance(filename, str) or not ASSET.fullmatch(filename) or
                not filename.startswith(name + "-") or
                not filename.endswith(f"-pg{major}-windows-x64.zip") or
                not isinstance(digest, str) or not SHA64.fullmatch(digest) or
                pg.get("downloadUrl") != url or filename not in assets or
                assets[filename].get("digest") != "sha256:" + digest):
                raise ValueError("Catalog ZIP does not match public Release")
            packages.append({
                "pgMajor": major, "asset": filename, "sha256": digest,
                "downloadUrl": url, "assetId": assets[filename]["id"],
            })
        records.append({
            "extension": name, "releaseTag": tag,
            "repositoryId": repository_id, "releaseId": release_id,
            "checksumsAssetId": assets["SHA256SUMS.txt"]["id"],
            "packages": packages,
        })
    return {
        "schemaVersion": SCHEMA,
        "repository": "pgextwin/catalog",
        "catalogCommit": commit,
        "catalogSha256": source_hashes,
        "postgresqlMajors": list(MAJORS),
        "extensionCount": 14,
        "zipCount": 70,
        "releases": records,
        "verificationLevel": "CATALOG_FEED_SIGNED_CLAIM_ONLY",
        "extensionSignatureVerified": False,
        "publicationAuthorized": False,
        "installAuthorized": False,
    }


def canonical(feed):
    return (json.dumps(feed, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True)
    opts = parser.parse_args()
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if not token:
        parser.error("Feed publisher requires job-scoped GitHub token")
    feed = build_feed(opts.catalog, opts.commit,
                      lambda repo, route: get_repo_json(repo, route, token))
    path = Path(opts.output)
    if path.exists() or path.is_symlink():
        raise ValueError("Refuse to overwrite old feed")
    path.write_bytes(canonical(feed))
    print(f"CATALOG_FEED_READY=70 HASH={hashlib.sha256(path.read_bytes()).hexdigest()} "
          "SIGNED=false PUBLISH=DENY")


if __name__ == "__main__":
    main()
