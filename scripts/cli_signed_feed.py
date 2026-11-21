#!/usr/bin/env python3
"""Exact approved Catalog -> single read-only public ZIP feed (v3) builder.

The builder runs only on a protected-main, completed-success Validate workflow
and reads public Release metadata with workflow-scoped GitHub access.
It NEVER promotes a candidate, creates extension Releases, signs, publishes
or upgrades original ZIP Sigstore trust.
"""
import argparse
import base64
from functools import cache
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

EXTENSION = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
LIMIT = 2_000_000
if __package__:
    from .release_inventory import ASSET, license_for, match_zip, release_assets, version_for
else:
    from release_inventory import ASSET, license_for, match_zip, release_assets, version_for


SCHEMA = "pgextwin-signed-catalog-zip-feed/v3"
OPTIONAL_MAJOR = "optionalPostgresqlMajor"
# Membership is the exact protected Catalog index used by authenticated,
# successful main CI and the pinned signer. Retirement may shrink that index;
# nonempty/resource/identifier checks do not prescribe historical membership.
MAX_FLEET = 128
MAX_MAJOR = 32


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
    return get_api_json("https://api.github.com/repos/" + repo + route, token)


def get_api_json(url, token):
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


def get_catalog_record(commit, name, token, protected_commits):
    if not SHA40.fullmatch(commit) or not EXTENSION.fullmatch(name):
        raise ValueError("Invalid historical Catalog lookup")
    if commit not in protected_commits():
        raise ValueError("Historical Catalog admission is outside protected main")
    path = f"extensions/{name}.json"
    file = get_api_json(f"https://api.github.com/repos/pgextwin/catalog/contents/{path}?ref={commit}", token)
    if file.get("type") != "file" or file.get("path") != path or file.get("encoding") != "base64":
        raise ValueError("Invalid historical Catalog contents response")
    content = base64.b64decode("".join(file["content"].splitlines()), validate=True)
    return strict_object(content.decode("utf-8"))


def verify_history_admission(name, snapshot, load_admission):
    tag = snapshot["releaseTag"]
    commit = snapshot["admission"]["catalogCommit"]
    if (not isinstance(commit, str) or not SHA40.fullmatch(commit) or
        not isinstance(tag, str) or not ASSET.fullmatch(tag)):
        raise ValueError(f"{name}: invalid Catalog Release admission")
    if load_admission is None:
        raise ValueError(f"{name}: historical Catalog admission loader required")
    try:
        record = load_admission(commit, name)
    except Exception as exc:
        raise ValueError(f"{name}: unable to load Catalog admission {commit}: {exc}") from exc

    try:
        if (record["name"] != name or record["repository"] != "pgextwin/" + name or
            record["latest"]["releaseTag"] != tag):
            raise ValueError(f"{name}: Catalog admission does not match historical Release {tag}")
        licenses = None
        if "releaseInventory" in record:
            current = record["releaseInventory"]["current"]
            if current["releaseTag"] != tag or not isinstance(current["licensesByMajor"], dict):
                raise ValueError(f"{name}: invalid Catalog admission license inventory for {tag}")
            licenses = current["licensesByMajor"]
        for row in snapshot["packages"]:
            major = row["pgMajor"]
            pg = record["postgresql"].get(major, {})
            if (pg.get("available") is not True or pg.get("asset") != row["asset"] or
                pg.get("sha256") != row["sha256"] or
                version_for(record["upstream"], major) != row["version"]):
                raise ValueError(f"{name}: Catalog admission ZIP or version mismatch for {tag} PG{major}")
            if licenses is not None and license_for(licenses.get(major)) != license_for(row.get("license")):
                raise ValueError(f"{name}: Catalog admission license evidence mismatch for {tag} PG{major}")
    except (AttributeError, KeyError, TypeError) as exc:
        raise ValueError(f"{name}: malformed historical Catalog admission for {tag}") from exc


def declared_majors(root):
    """Fail-closed PG cohort configured in the protected, signed-feed source commit."""
    raw = source_bytes(root, "config/cli-feed-majors.json")
    matrix = strict_object(raw.decode("utf-8"))
    if type(matrix) is not dict or set(matrix) - {OPTIONAL_MAJOR} != {"schemaVersion", "postgresqlMajors"} or (
        type(matrix["schemaVersion"]) is not int or matrix["schemaVersion"] != 1
    ):
        raise ValueError("Unknown signed-feed PG support policy")
    values = matrix["postgresqlMajors"]
    if (type(values) is not list or not 1 <= len(values) <= 12 or
        any(type(item) is not str or not re.fullmatch(r"[1-9][0-9]*", item)
            for item in values) or
        any(not 14 <= int(item) <= MAX_MAJOR for item in values) or
        [int(item) for item in values] !=
            list(range(int(values[0]), int(values[0]) + len(values)))):
        raise ValueError("Unsafe or noncontiguous protected PostgreSQL cohort")
    optional = matrix.get(OPTIONAL_MAJOR)
    if OPTIONAL_MAJOR in matrix and (
        len(values) == 12 or int(values[-1]) == MAX_MAJOR or
        optional != str(int(values[-1]) + 1)
    ):
        raise ValueError("Unsafe optional PostgreSQL major")
    return tuple(values), optional


def build_feed(root, commit, load, *, load_admission=None):
    """Project the protected Catalog's current and approved historical ZIPs."""
    root = Path(root)
    if not SHA40.fullmatch(commit):
        raise ValueError("Full protected Catalog commit required")
    majors, optional = declared_majors(root)
    index = strict_object(source_bytes(root, "index.json").decode("utf-8"))
    names = index["extensions"]
    if index.get("schemaVersion") != 2 or not isinstance(names, list) or not 1 <= len(names) <= MAX_FLEET or (
        any(not isinstance(n, str) or len(n) > 64 or not EXTENSION.fullmatch(n) for n in names) or
        names != sorted(names) or len(names) != len(set(names)) or
        sorted(p.stem for p in (root / "extensions").glob("*.json")) != names
    ):
        raise ValueError("Catalog extension inventory incomplete")
    records = [strict_object(source_bytes(root, f"extensions/{name}.json").decode("utf-8"))
               for name in names]
    supported = majors
    if optional and any(r["postgresql"].get(optional, {}).get("available") is True for r in records):
        supported += (optional,)
    extensions = []
    for name, data in zip(names, records, strict=True):
        repo = "pgextwin/" + name
        latest_tag = data["latest"]["releaseTag"]
        if (data["name"] != name or data["repository"] != repo or
            data["schemaVersion"] != 2 or data["architecture"] != "x64"):
            raise ValueError("Unsafe Catalog record identity")
        pg_matrix = data["postgresql"]
        # The protected cohort admits required majors and the optional latest subset.
        if (not set(majors).issubset(pg_matrix) or
            any(not re.fullmatch(r"[1-9][0-9]*", major) or
                (major not in majors and major != optional and not 14 <= int(major) < int(majors[0]))
                for major in pg_matrix)):
            raise ValueError("Catalog major set differs from protected PG cohort")
        inventory = data.get("releaseInventory", {})
        current = inventory.get("current", {})
        if current.get("releaseTag") != latest_tag:
            raise ValueError(f"{name}: missing or mismatched latest license evidence")
        latest_packages = []
        for major in supported:
            pg = pg_matrix.get(major, {})
            if major == optional and pg.get("available") is not True:
                continue
            if pg.get("available") is not True:
                raise ValueError("Incomplete signed-feed cohort availability")
            latest_packages.append({
                "pgMajor": major, "version": version_for(data["upstream"], major),
                "asset": pg["asset"], "sha256": pg["sha256"], "downloadUrl": pg["downloadUrl"],
                "license": current["licensesByMajor"].get(major),
            })

        releases = {latest_tag: {"admission": {"catalogCommit": commit}, "packages": latest_packages}}
        tags = {latest_tag}
        for snapshot in inventory["history"]:
            verify_history_admission(name, snapshot, load_admission)
            tag = snapshot["releaseTag"]
            if tag in tags:
                raise ValueError("Duplicate Catalog Release tag")
            tags.add(tag)
            packages = [row for row in snapshot["packages"] if row["pgMajor"] in supported]
            if packages:
                releases[tag] = {**snapshot, "packages": packages}

        repo_data = load(repo, "")
        repository_id = repo_data.get("id")
        if repo_data.get("full_name") != repo or type(repository_id) is not int or repository_id <= 0:
            raise ValueError("Public repository identity mismatch")
        signed = []
        keys = set()
        for tag, candidate in sorted(releases.items()):
            admission = candidate["admission"]["catalogCommit"]
            if not isinstance(tag, str) or not ASSET.fullmatch(tag) or not SHA40.fullmatch(admission):
                raise ValueError("Invalid Catalog Release admission")
            release_id, assets = release_assets(repo, tag, load(repo, "/releases/tags/" + tag))
            if tag != latest_tag and (type(candidate["releaseId"]) is not int or
                                      candidate["releaseId"] != release_id):
                raise ValueError("Catalog history does not match public Release ID")
            packages = []
            release_majors = set()
            for pg in sorted(candidate["packages"], key=lambda row: int(row["pgMajor"])):
                major, version = pg["pgMajor"], pg["version"]
                if (not isinstance(version, str) or not version.strip()
                    or (major, version) in keys or major in release_majors):
                    raise ValueError("Missing or duplicate Catalog package version")
                keys.add((major, version))
                release_majors.add(major)
                license_info = license_for(pg.get("license"))
                if tag != latest_tag and "assetId" not in pg:
                    raise ValueError("Missing Catalog historical ZIP asset ID")
                asset_id = match_zip(repo, tag, major, pg, assets)
                packages.append({
                    "pgMajor": major, "version": version, "asset": pg["asset"],
                    "assetId": asset_id, "sha256": pg["sha256"], "license": license_info,
                })
            signed.append({
                "releaseTag": tag, "releaseId": release_id, "admission": {"catalogCommit": admission},
                "packages": packages,
            })
        extensions.append({"extension": name, "repositoryId": repository_id,
                           "latestReleaseTag": latest_tag, "releases": signed})

    feed = {
        "schemaVersion": SCHEMA,
        "repository": "pgextwin/catalog",
        "catalogCommit": commit,
        "postgresqlMajors": list(majors),
        "extensions": extensions,
        "verificationLevel": "CATALOG_FEED_SIGNED_CLAIM_ONLY",
        "extensionSignatureVerified": False,
        "publicationAuthorized": False,
        "installAuthorized": False,
    }
    if optional in supported:
        feed[OPTIONAL_MAJOR] = optional
    return feed


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
    path = Path(opts.output)
    if path.exists() or path.is_symlink():
        raise ValueError("Refuse to overwrite feed output")

    @cache
    def protected_commits():
        # Only first-parent commits represent Catalog states accepted on main.
        return frozenset(subprocess.check_output(
            ["git", "rev-list", "--first-parent", "refs/remotes/origin/main"],
            cwd=opts.catalog, text=True).splitlines())

    feed = build_feed(opts.catalog, opts.commit,
                      lambda repo, route: get_repo_json(repo, route, token),
                      load_admission=lambda commit, name: get_catalog_record(commit, name, token, protected_commits))
    data = canonical(feed)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("Signed Catalog feed exceeds 2MiB reader cap")
    with path.open("xb") as output:
        output.write(data)
    count = sum(len(r["packages"]) for e in feed["extensions"] for r in e["releases"])
    print(f"CATALOG_FEED_READY={count} HASH={hashlib.sha256(data).hexdigest()} "
          f"ASSET={path.name} SIGNED=false PUBLISH=DENY")


if __name__ == "__main__":
    main()
