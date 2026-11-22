"""Package ledger and the materialized Catalog v2 consumer view."""

import argparse
import json
import re
import subprocess
from functools import cache
from pathlib import Path

if __package__:
    from .release_inventory import ASSET, SHA64, license_for, match_zip, release_assets, version_for
else:
    from release_inventory import ASSET, SHA64, license_for, match_zip, release_assets, version_for


DIRECTORY = "packages"
NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
MAJOR = re.compile(r"[1-9][0-9]?\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
LIMIT = 2_000_000
ZIP_FIELDS = ("pgMajor", "version", "asset", "assetId", "sha256", "license")


def strict_object(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=unique)


def json_bytes(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def read_record(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError(f"Missing, linked, or oversized file: {path}")
    return strict_object(path.read_text(encoding="utf-8"))


def current_release(ledger):
    release_id = ledger["latestReleaseId"]
    matches = [release for release in ledger["releases"] if release["releaseId"] == release_id]
    if type(release_id) is not int or len(matches) != 1:
        raise ValueError("Ledger latestReleaseId must identify exactly one Release")
    if "admission" in matches[0] or "legacyInventoryCommit" in matches[0]:
        raise ValueError("Latest Release must use the projected Catalog source as its admission")
    return matches[0]


def pin_release(record, release, licenses):
    """Attach IDs from the Release whose public ZIP metadata has been verified."""
    latest = record["latest"]
    repo, tag = record["repository"], latest["releaseTag"]
    release_id, assets = release_assets(repo, tag, release)
    if (release.get("prerelease") is not False or release["published_at"] != latest["publishedAt"]
            or release.get("html_url") != latest["releaseUrl"]):
        raise ValueError("Catalog-public Release identity mismatch")
    packages = []
    for major, row in sorted(record["postgresql"].items(), key=lambda item: int(item[0])):
        if row["available"] is False:
            continue
        package = {
            "pgMajor": major,
            "version": version_for(record["upstream"], major),
            "asset": row["asset"],
            "assetId": match_zip(repo, tag, major, row, assets),
            "sha256": row["sha256"],
            "license": license_for(licenses.get(major)),
        }
        ref = record["upstream"].get("perPostgresql", {}).get(major, {}).get("ref")
        if ref is not None:
            package["upstreamRef"] = ref
        package["evidence"] = row["evidence"]
        packages.append(package)
    return {"releaseTag": tag, "releaseId": release_id, "publishedAt": latest["publishedAt"],
            "checksumsAsset": latest["checksumsAsset"], "packages": packages}


def ledger_record(record, repository_id, latest, history):
    metadata = {key: value for key, value in record.items() if key not in
                ("schemaVersion", "upstream", "latest", "postgresql", "releaseInventory")}
    upstream = {"repository": record["upstream"]["repository"]}
    packages = {row["pgMajor"] for row in latest["packages"]}
    if "perPostgresql" in record["upstream"]:
        upstream["versionScheme"] = "perPostgresql"
        unpublished = {major: info for major, info in record["upstream"]["perPostgresql"].items()
                       if major not in packages}
        if unpublished:
            upstream["unpublishedByMajor"] = unpublished
    return {
        "schemaVersion": 1, **metadata, "upstream": upstream, "repositoryId": repository_id,
        "latestReleaseId": latest["releaseId"],
        "unavailableMajors": sorted((major for major, row in record["postgresql"].items()
                                     if row["available"] is False), key=int),
        "releases": sorted([latest, *history], key=lambda release: release["releaseTag"]),
    }


def website_record(ledger):
    """Keep the public extensions/<name>.json Catalog v2 contract."""
    latest = current_release(ledger)
    tag, repo = latest["releaseTag"], ledger["repository"]
    upstream = {"repository": ledger["upstream"]["repository"]}
    packages = latest["packages"]
    if ledger["upstream"].get("versionScheme") == "perPostgresql":
        versions = dict(ledger["upstream"].get("unpublishedByMajor", {}))
        for row in packages:
            version = {"version": row["version"]}
            if "upstreamRef" in row:
                version["ref"] = row["upstreamRef"]
            versions[row["pgMajor"]] = version
        upstream["perPostgresql"] = dict(sorted(versions.items(), key=lambda item: int(item[0])))
    else:
        versions = {row["version"] for row in packages}
        if len(versions) != 1:
            raise ValueError("Shared upstream version differs between latest packages")
        upstream["version"] = versions.pop()
    matrix = {major: {"available": False} for major in ledger["unavailableMajors"]}
    for row in packages:
        major, asset = row["pgMajor"], row["asset"]
        if major in matrix:
            raise ValueError("Conflicting Catalog package availability")
        matrix[major] = {
            "available": True, "asset": asset,
            "downloadUrl": f"https://github.com/{repo}/releases/download/{tag}/{asset}",
            "sha256": row["sha256"], "evidence": row["evidence"],
        }
    return {
        "schemaVersion": 2,
        "name": ledger["name"], "displayName": ledger["displayName"],
        "description": ledger["description"], "upstream": upstream,
        "repository": repo, "license": ledger["license"], "architecture": ledger["architecture"],
        "latest": {
            "releaseTag": tag, "publishedAt": latest["publishedAt"],
            "releaseUrl": f"https://github.com/{repo}/releases/tag/{tag}",
            "checksumsAsset": latest["checksumsAsset"],
        },
        "postgresql": dict(sorted(matrix.items(), key=lambda item: int(item[0]))),
        "runtime": ledger["runtime"], "capabilities": ledger["capabilities"],
        "capabilitiesSource": ledger["capabilitiesSource"],
        **({"externalSourceRegistry": ledger["externalSourceRegistry"]}
           if "externalSourceRegistry" in ledger else {}),
    }


def superseded_releases(ledger, latest, previous_admission):
    """Keep only distinct older versions, with their original ZIP and license pins."""
    current = current_release(ledger)
    if ((latest["releaseTag"] == current["releaseTag"]) !=
            (latest["releaseId"] == current["releaseId"])):
        raise ValueError("Previously admitted Release tag or ID changed")
    versions = {(row["pgMajor"], row["version"]) for row in latest["packages"]}
    history = []
    for release in ledger["releases"]:
        if release["releaseId"] == latest["releaseId"]:
            continue
        packages = [row for row in release["packages"] if (row["pgMajor"], row["version"]) not in versions]
        if not packages:
            continue
        retired = {**release, "packages": packages}
        if release["releaseId"] == current["releaseId"]:
            retired["admission"] = {"catalogCommit": previous_admission()}
        history.append(retired)
    return history


def git_admissions(root):
    """Read Catalog admissions only from regular blobs on protected main's first parent."""
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root)

    commits = set(git("rev-list", "--first-parent", "refs/remotes/origin/main").decode().splitlines())

    @cache
    def load(commit, name):
        if not COMMIT.fullmatch(commit) or not NAME.fullmatch(name) or commit not in commits:
            raise ValueError("Historical Catalog admission is outside protected main")
        # An admission from the ledger era must use the canonical record.
        directory = DIRECTORY if git("ls-tree", commit, "--", DIRECTORY) else "extensions"
        path = f"{directory}/{name}.json"
        entry = git("ls-tree", commit, "--", path)
        if not entry.startswith(b"100644 blob "):
            raise ValueError(f"Historical Catalog record is not a regular file: {path}")
        blob = entry.split()[2].decode()
        if int(git("cat-file", "-s", blob)) > LIMIT:
            raise ValueError(f"Oversized historical Catalog record: {path}")
        return strict_object(git("cat-file", "blob", blob).decode("utf-8"))

    return load


def verify_legacy_inventory(name, snapshot, load_admission):
    """Verify migrated asset IDs and license evidence against protected v2 history."""
    commit = snapshot["legacyInventoryCommit"]
    record = load_admission(commit, name)
    if record["name"] != name or record["repository"] != f"pgextwin/{name}":
        raise ValueError(f"{name}: legacy inventory admission identity mismatch")
    for release in record["releaseInventory"]["history"]:
        if (release["releaseTag"] == snapshot["releaseTag"] and
                release["releaseId"] == snapshot["releaseId"] and
                release["admission"] == snapshot["admission"]):
            rows = {tuple(row[key] for key in ZIP_FIELDS[:-1]): row["license"] for row in release["packages"]}
            if all(rows.get(tuple(row[key] for key in ZIP_FIELDS[:-1])) ==
                   license_for(row["license"]) for row in snapshot["packages"]):
                return
    raise ValueError(f"{name}: historical license evidence is outside its protected admission")


def main():
    parser = argparse.ArgumentParser(description="Regenerate a Catalog v2 Website record from the ledger.")
    parser.add_argument("extension")
    args = parser.parse_args()
    name = args.extension
    if not NAME.fullmatch(name):
        parser.error("Invalid extension name")
    filename = name + ".json"
    ledger = read_record(Path(DIRECTORY) / filename)
    if ledger["name"] != name or ledger["repository"] != "pgextwin/" + name:
        parser.error("Ledger name or repository does not match the extension")
    (Path("extensions") / filename).write_bytes(json_bytes(website_record(ledger)))


if __name__ == "__main__":
    main()
