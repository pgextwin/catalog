#!/usr/bin/env python3
"""Exact approved Catalog -> single read-only public ZIP feed (v3) builder.

The publication workflow runs this projection on the exact protected-main
commit from a completed-success Validate workflow. The v3 wire format stays
compatible with published CLI versions.
"""
import argparse
import base64
import hashlib
import json
import re
import urllib.request
from pathlib import Path

EXTENSION = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
LIMIT = 2_000_000
if __package__:
    from . import package_ledger as ledger
    from .release_inventory import ASSET, license_for, match_zip, release_assets, version_for
else:
    import package_ledger as ledger
    from release_inventory import ASSET, license_for, match_zip, release_assets, version_for


SCHEMA = "pgextwin-signed-catalog-zip-feed/v3"
OPTIONAL_MAJOR = "optionalPostgresqlMajor"
# Membership is the exact protected Catalog index used by authenticated,
# successful main CI and the pinned signer. Retirement may shrink that index;
# nonempty/resource/identifier checks do not prescribe historical membership.
MAX_FLEET = 128
MAX_MAJOR = 32


strict_object = ledger.strict_object


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


def declared_majors(root, *, first_supported=15):
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
        any(not first_supported <= int(item) <= MAX_MAJOR for item in values) or
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


def catalog_names(root, directory):
    index = strict_object(source_bytes(root, "index.json").decode("utf-8"))
    schema_version = index.get("schemaVersion")
    if type(schema_version) is not int or schema_version not in (2, 3):
        raise ValueError("Catalog extension inventory incomplete")
    names = index.get("extensions")
    if (
        not isinstance(names, list)
        or not 1 <= len(names) <= MAX_FLEET
        or any(not isinstance(n, str) or len(n) > 64 or not EXTENSION.fullmatch(n) for n in names)
        or names != sorted(names)
        or len(names) != len(set(names))
    ):
        raise ValueError("Catalog extension inventory incomplete")
    if schema_version == 3:
        if (
            set(index) != {"schemaVersion", "identitiesDir", "packagesDir", "extensions", "identities"}
            or index.get("identitiesDir") != "identities"
            or index.get("packagesDir") != ledger.DIRECTORY
            or directory != ledger.DIRECTORY
        ):
            raise ValueError("Catalog extension inventory incomplete")
        identities = index.get("identities")
        if not isinstance(identities, list) or not identities:
            raise ValueError("Catalog extension inventory incomplete")
        seen = set()
        distributed = []
        for entry in identities:
            if (
                type(entry) is not dict
                or not {"name", "path", "intakeClass"}.issubset(entry)
                or not set(entry).issubset({"name", "path", "intakeClass", "ledgerPath"})
            ):
                raise ValueError("Catalog extension inventory incomplete")
            name = entry["name"]
            intake_class = entry["intakeClass"]
            if (
                not isinstance(name, str)
                or len(name) > 64
                or not EXTENSION.fullmatch(name)
                or name in seen
                or entry["path"] != f"identities/{name}.json"
                or intake_class not in ("distributed", "research-only")
            ):
                raise ValueError("Catalog extension inventory incomplete")
            seen.add(name)
            if intake_class == "distributed":
                if entry.get("ledgerPath") != f"{ledger.DIRECTORY}/{name}.json":
                    raise ValueError("Catalog extension inventory incomplete")
                distributed.append(name)
            elif "ledgerPath" in entry:
                raise ValueError("Catalog extension inventory incomplete")
        if [entry["name"] for entry in identities] != sorted(seen) or distributed != names:
            raise ValueError("Catalog extension inventory incomplete")
    if sorted(p.stem for p in (root / directory).glob("*.json")) != names:
        raise ValueError("Catalog extension inventory incomplete")
    return names


def verify_ledger_admission(name, repository_id, release, load_admission):
    commit = release["admission"]["catalogCommit"]
    admitted = load_admission(commit, name)
    if admitted.get("schemaVersion") == 1:
        original = ledger.current_release(admitted)
        recorded = {row["pgMajor"]: row for row in original["packages"]}
        if (admitted["name"] != name or admitted["repository"] != "pgextwin/" + name or
                admitted["repositoryId"] != repository_id or
                original["releaseId"] != release["releaseId"] or
                original["releaseTag"] != release["releaseTag"] or
                any(recorded.get(row["pgMajor"]) != row for row in release["packages"])):
            raise ValueError(f"{name}: historical package differs from protected Catalog admission")
    else:
        verify_history_admission(name, release, load_admission)
        ledger.verify_legacy_inventory(name, release, load_admission)


def build_feed(root, commit, load=None, *, load_admission=None):
    """Build v3 from the protected ledger. Explicit loaders support v2 replay."""
    if load is not None:
        return build_legacy_feed(root, commit, load, load_admission=load_admission)

    root = Path(root)
    if not SHA40.fullmatch(commit):
        raise ValueError("Full protected Catalog commit required")
    majors, optional = declared_majors(root)
    names = catalog_names(root, ledger.DIRECTORY)
    records = [ledger.read_record(root / ledger.DIRECTORY / (name + ".json")) for name in names]
    load_admission = load_admission or ledger.git_admissions(root)
    latest = [ledger.current_release(record) for record in records]
    if optional and not any(row["pgMajor"] == optional for release in latest for row in release["packages"]):
        optional = None
    allowed = set(majors) | ({optional} if optional else set())
    extensions = []
    for name, record, current in zip(names, records, latest, strict=True):
        repository_id = record["repositoryId"]
        if (record["schemaVersion"] != 1 or record["name"] != name or
                record["repository"] != "pgextwin/" + name or record["architecture"] != "x64" or
                type(repository_id) is not int or repository_id <= 0):
            raise ValueError("Unsafe Catalog ledger identity")
        signed = []
        tags, release_ids, asset_ids, versions = set(), set(), set(), set()
        for release in sorted(record["releases"], key=lambda row: row["releaseTag"]):
            tag, release_id = release["releaseTag"], release["releaseId"]
            if (not ASSET.fullmatch(tag) or tag in tags or type(release_id) is not int or
                    release_id <= 0 or release_id in release_ids or not release["packages"]):
                raise ValueError(f"{name}: invalid or duplicate Catalog Release identity")
            tags.add(tag)
            release_ids.add(release_id)
            current_release = release is current
            if not current_release:
                verify_ledger_admission(name, repository_id, release, load_admission)

            packages = []
            release_majors = set()
            for row in sorted(release["packages"], key=lambda row: int(row["pgMajor"])):
                major, version, asset, asset_id, digest, license_info = (
                    row[field] for field in ledger.ZIP_FIELDS)
                if (not ledger.MAJOR.fullmatch(major) or not isinstance(version, str) or
                        not version.strip() or (major, version) in versions or major in release_majors or
                        not ASSET.fullmatch(asset) or not asset.startswith(name + "-") or
                        not asset.endswith(f"-pg{major}-windows-x64.zip") or not ledger.SHA64.fullmatch(digest) or
                        type(asset_id) is not int or asset_id <= 0 or asset_id in asset_ids):
                    raise ValueError(f"{name}: invalid or duplicate Catalog package for {tag} PG{major}")
                license_for(license_info)
                release_majors.add(major)
                versions.add((major, version))
                asset_ids.add(asset_id)
                if major in allowed:
                    packages.append({field: row[field] for field in ledger.ZIP_FIELDS})
            if current_release and (not set(majors) <= release_majors or
                    any(major not in allowed and not 14 <= int(major) < int(majors[0])
                        for major in release_majors)):
                raise ValueError(f"{name}: incomplete or unexpected latest signed-feed cohort")
            if packages:
                admission = {"catalogCommit": commit} if current_release else release["admission"]
                signed.append({"releaseTag": tag, "releaseId": release_id, "admission": admission,
                               "packages": packages})
        extensions.append({"extension": name, "repositoryId": repository_id,
                           "latestReleaseTag": current["releaseTag"], "releases": signed})

    return feed_document(commit, majors, optional, extensions)


def build_legacy_feed(root, commit, load, *, load_admission=None):
    """Replay v2 Catalog snapshots with explicit Release and admission loaders."""
    root = Path(root)
    if not SHA40.fullmatch(commit):
        raise ValueError("Full protected Catalog commit required")
    majors, optional = declared_majors(root, first_supported=14)
    names = catalog_names(root, "extensions")
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

    return feed_document(commit, majors, optional if optional in supported else None, extensions)


def feed_document(commit, majors, optional, extensions):
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
    if optional is not None:
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
    path = Path(opts.output)
    if path.exists() or path.is_symlink():
        raise ValueError("Refuse to overwrite feed output")
    feed = build_feed(opts.catalog, opts.commit)
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
