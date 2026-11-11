#!/usr/bin/env python3
"""Compare UNTRUSTED stable provider Release metadata with tracked source pins.

Reporting only: this script does NOT authenticate original asset bytes, approve
downloads, change signed cohorts, create releases, or post GitHub comments.
Provider tag versions are RELEASE versions, not necessarily extension versions.
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ROOT / "external/discovery-providers-v1.json"
COHORT = ROOT / "external/signed-direct-get/qualified_cohort/latest.json"
LEDGERS = (
    ROOT / "external/windows-candidates-v1.json",
    ROOT / "external/windows-candidates-portalcorp-v1.json",
)
HISTORICAL_ADMISSIONS = ROOT / "external/signed-direct-get"
SEMVER = re.compile(r"v?([0-9]+(?:[.][0-9]+){1,3})\Z")
ORACLE = re.compile(r"ORACLE_FDW_([0-9]+_[0-9]+_[0-9]+)\Z")
DATE = re.compile(r"v?(20[0-9]{6})\Z")


def tag_key(tag):
    """Only stable numeric RELEASE tags; never treat rc/beta as a new stable."""
    if not isinstance(tag, str):
        return None
    oracle = ORACLE.fullmatch(tag)
    if oracle:
        values = oracle.group(1).split("_")
    else:
        match = SEMVER.fullmatch(tag)
        if match:
            values = match.group(1).split(".")
        else:
            match = DATE.fullmatch(tag)
            if not match:
                return None
            values = [match.group(1)]
    numbers = tuple(map(int, values))
    return numbers + (0,) * (4 - len(numbers))


def tracked_assets(cohort, ledgers, historical_admissions=()):
    if cohort.get("schemaVersion") != "pgextwin-external-latest-original-pins/v1":
        raise ValueError("Unknown cohort reference schema")
    results = {}
    for record in cohort["records"]:
        results.setdefault(record["sourceRepo"].lower(), set()).add(
            (record["releaseTag"], record["assetId"]))
    for ledger in ledgers:
        if (ledger.get("schemaVersion") != "pgextwin-windows-source-candidates/v1" or
            ledger.get("publicationAuthorized") is not False or
            ledger.get("redistributionAuthorized") is not False):
            raise ValueError("Unknown or promoted candidate ledger")
        for record in ledger["candidates"]:
            results.setdefault(record["sourceRepo"].lower(), set()).add(
                (record["releaseTag"], record["assetId"]))
    # Historical issuer receipts are tracking evidence only. Even an expired
    # or once-approved admission grants NO new access through this watcher.
    for receipt in historical_admissions:
        if (receipt.get("schemaVersion") != "pgextwin-external-direct-get-admission/v1" or
            receipt.get("sourceKind") != "EXTERNAL_GITHUB_RELEASE_ASSET" or
            receipt.get("mirrorAuthorized") is not False or
            receipt.get("redistributionAuthorized") is not False):
            raise ValueError("Malformed historical issuer receipt reference")
        for record in receipt["records"]:
            results.setdefault(record["sourceRepo"].lower(), set()).add(
                (record["releaseTag"], record["assetId"]))
    return results


def analyze(inventory, provider_config, known):
    if (inventory.get("schemaVersion") != "pgextwin-external-windows-release-inventory/v1" or
        inventory.get("trust") != "UNVERIFIED_METADATA_ONLY" or
        inventory.get("publicationAuthorized") is not False or
        inventory.get("redistributionAuthorized") is not False or
        provider_config.get("trust") != "READ_ONLY_METADATA_NEVER_AUTHORIZE"):
        raise ValueError("Invalid source inventory trust boundary")
    declared = {p["repo"].lower(): p for p in provider_config["providers"]}
    repositories = inventory["repositories"]
    if {r["repo"].lower() for r in repositories} != set(declared) or len(repositories) != len(declared):
        raise ValueError("Missing, duplicate, or extra discovery provider")
    rows = []
    for repository in repositories:
        repo = repository["repo"]
        tracked = known.get(repo.lower(), set())
        stable = [
            r for r in repository["releases"]
            if r["draft"] is False and r["prerelease"] is False
            and r["windowsAssets"] and tag_key(r["tag"]) is not None
        ]
        if not stable:
            rows.append({"repo": repo, "extension": declared[repo.lower()]["extension"],
                         "status": "NO_STABLE_WINDOWS_RELEASE", "latestTag": None,
                         "untrackedAssets": [], "trackedAssets": 0})
            continue
        release = max(stable, key=lambda r: (
            tag_key(r["tag"]), r.get("publishedAt") or "", r["releaseId"]))
        ids = [(release["tag"], a["assetId"]) for a in release["windowsAssets"]]
        new = [a["name"] for a, ident in zip(release["windowsAssets"], ids)
               if ident not in tracked]
        historical_tags = [tag_key(tag) for tag, _ in tracked if tag_key(tag) is not None]
        # A provider with no qualified pin or candidate ledger has no
        # baseline to establish a *newer* version. Report this inventory
        # coverage gap separately rather than a false upgrade alert.
        newer = bool(historical_tags) and tag_key(release["tag"]) > max(historical_tags)
        status = ("BASELINE_NOT_ESTABLISHED" if not historical_tags else
                  "NEW_STABLE_RELEASE" if new and newer else
                  "UNTRACKED_ASSET_IN_KNOWN_VERSION" if new else "TRACKED")
        rows.append({"repo": repo, "extension": declared[repo.lower()]["extension"],
                     "status": status, "latestTag": release["tag"],
                     "latestReleaseId": release["releaseId"],
                     "untrackedAssets": sorted(new),
                     "trackedAssets": len(ids) - len(new)})
    rows.sort(key=lambda r: r["repo"].lower())
    return {"schemaVersion": "pgextwin-external-stable-release-watch/v1",
            "trust": "UNVERIFIED_METADATA_ONLY", "publicationAuthorized": False,
            "downloadAuthorized": False, "redistributionAuthorized": False,
            "tagMeaning": "PROVIDER_RELEASE_VERSION_NOT_EXTENSION_VERSION",
            "providers": rows,
            "newStableCount": sum(r["status"] == "NEW_STABLE_RELEASE" for r in rows),
            "baselineMissingCount": sum(r["status"] == "BASELINE_NOT_ESTABLISHED" for r in rows),
            "untrackedAssetProviderCount": sum(
                r["status"] == "UNTRACKED_ASSET_IN_KNOWN_VERSION" for r in rows)}


# Official GitHub Release metadata baseline, not an issuer or download permission.
PGROONGA_WATCH_BASELINE = ROOT / "external/pgroonga-release-watch-baseline-v1.json"
TIMESCALEDB_WATCH_BASELINE = ROOT / "external/timescaledb-release-watch-baseline-v1.json"


def unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate PGroonga baseline JSON key")
        result[key] = value
    return result


def reviewed_pgroonga_baseline(document, inventory):
    """Track the existing 5 exact original ZIP IDs without authorizing them.

    A changed live GitHub asset size/digest is an integrity alarm, not a new
    admissible artifact. The independent per-major original pins are reused.
    """
    from issue112_pgroonga_rights_audit import (
        PINS as original_pins, VERSION as source_version, original_name
    )

    if (type(document) is not dict or set(document) != {
            "schemaVersion", "trust", "sourceRepo", "releaseTag", "releaseId",
            "downloadAuthorized", "publicationAuthorized",
            "redistributionAuthorized", "records"}
            or document["schemaVersion"] !=
            "pgextwin-issue112-pgroonga-official-release-watch-baseline/v1"
            or document["trust"] != "UNVERIFIED_METADATA_NEVER_AUTHORIZE"
            or document["sourceRepo"] != "pgroonga/pgroonga"
            or document["releaseTag"] != source_version
            or type(document["releaseId"]) is not int
            or document["releaseId"] <= 0
            or any(document[flag] is not False for flag in (
                "downloadAuthorized", "publicationAuthorized",
                "redistributionAuthorized"))):
        raise ValueError("Invalid PGroonga read-only watch baseline")

    records = document["records"]
    if type(records) is not list or len(records) != 5:
        raise ValueError("Incomplete PGroonga original-release matrix")
    expected = {}
    for record in records:
        if type(record) is not dict or set(record) != {
                "pgMajor", "assetId", "assetName", "originalBytes",
                "originalSha256"}:
            raise ValueError("Malformed PGroonga asset baseline")
        major = record["pgMajor"]
        if (type(major) is not str or major not in ("14", "15", "16", "17", "18")
                or major in expected or type(record["assetId"]) is not int
                or record["assetId"] <= 0
                or record["assetName"] != original_name(int(major))
                or (record["originalBytes"], record["originalSha256"])
                != original_pins[int(major)]):
            raise ValueError("PGroonga baseline mismatches independent original pins")
        expected[major] = record
    if set(expected) != {"14", "15", "16", "17", "18"} or len({
            row["assetId"] for row in records}) != 5:
        raise ValueError("Missing/duplicate PGroonga Release asset ID")

    providers = [r for r in inventory.get("repositories", [])
                 if r.get("repo", "").lower() == "pgroonga/pgroonga"]
    if len(providers) != 1:
        raise ValueError("PGroonga source missing/duplicated in live scan")
    releases = [r for r in providers[0]["releases"]
                if r["releaseId"] == document["releaseId"]]
    if len(releases) != 1 or releases[0]["tag"] != source_version or (
            releases[0]["draft"] is not False or
            releases[0]["prerelease"] is not False):
        raise ValueError("PGroonga observed release identity drift")
    assets = {a["assetId"]: a for a in releases[0]["windowsAssets"]}
    for record in records:
        live = assets.get(record["assetId"])
        if (live is None or live.get("name") != record["assetName"]
                or live.get("size") != record["originalBytes"]
                or live.get("digest") != "sha256:" + record["originalSha256"]
                or live.get("state") != "uploaded"):
            raise ValueError("PGroonga exact original metadata changed or disappeared")
    return {(document["releaseTag"], row["assetId"]) for row in records}



def reviewed_timescaledb_baseline(document, inventory):
    """Monitor exact GitHub API identities, NOT independently rehashed ZIP bytes."""
    if (type(document) is not dict or set(document) != {
            "schemaVersion", "trust", "sourceRepo", "releaseTag", "releaseId",
            "downloadAuthorized", "publicationAuthorized",
            "redistributionAuthorized", "records"}
            or document["schemaVersion"] !=
            "pgextwin-issue112-timescaledb-official-release-watch-baseline/v1"
            or document["trust"] != "UNVERIFIED_API_DIGEST_NEVER_AUTHORIZE"
            or document["sourceRepo"] != "timescale/timescaledb"
            or document["releaseTag"] != "2.31.0"
            or type(document["releaseId"]) is not int
            or document["releaseId"] <= 0
            or any(document[flag] is not False for flag in (
                "downloadAuthorized", "publicationAuthorized",
                "redistributionAuthorized"))):
        raise ValueError("Invalid TimescaleDB read-only baseline")
    records = document["records"]
    if type(records) is not list or len(records) != 3:
        raise ValueError("Incomplete TimescaleDB baseline")
    expected = {}
    for row in records:
        if type(row) is not dict or set(row) != {
                "pgMajor", "assetId", "assetName", "apiBytes", "apiSha256"}:
            raise ValueError("Malformed TimescaleDB asset")
        major = row["pgMajor"]
        if (type(major) is not str or major not in ("16", "17", "18")
                or major in expected or type(row["assetId"]) is not int
                or row["assetId"] <= 0
                or row["assetName"] !=
                f"timescaledb-postgresql-{major}-windows-amd64.zip"
                or type(row["apiBytes"]) is not int or row["apiBytes"] <= 0
                or type(row["apiSha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", row["apiSha256"]) is None):
            raise ValueError("Unsafe TimescaleDB API asset")
        expected[major] = row
    if set(expected) != {"16", "17", "18"} or len({
            row["assetId"] for row in records}) != 3:
        raise ValueError("Duplicate or missing TimescaleDB asset ID")
    providers = [r for r in inventory.get("repositories", [])
                 if r.get("repo", "").lower() == "timescale/timescaledb"]
    if len(providers) != 1:
        raise ValueError("TimescaleDB discovery source missing or duplicated")
    releases = [r for r in providers[0]["releases"]
                if r["releaseId"] == document["releaseId"]]
    if (len(releases) != 1 or releases[0]["tag"] != document["releaseTag"]
            or releases[0]["draft"] is not False
            or releases[0]["prerelease"] is not False):
        raise ValueError("TimescaleDB Release identity drift")
    assets = {a["assetId"]: a for a in releases[0]["windowsAssets"]}
    if len(assets) != len(records):
        raise ValueError("TimescaleDB baseline asset set changed")
    for row in records:
        live = assets.get(row["assetId"])
        if (live is None or live.get("name") != row["assetName"]
                or live.get("size") != row["apiBytes"]
                or live.get("digest") != "sha256:" + row["apiSha256"]
                or live.get("state") != "uploaded"):
            raise ValueError("TimescaleDB GitHub API asset drift")
    return {(document["releaseTag"], row["assetId"]) for row in records}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    providers = json.loads(PROVIDERS.read_text(encoding="utf-8"))
    # Keep existing strict allowlist validation instead of weakening providers.
    from discover_external_windows_releases import config_providers
    config_providers(providers)
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    cohort = json.loads(COHORT.read_text(encoding="utf-8"))
    ledgers = [json.loads(f.read_text(encoding="utf-8")) for f in LEDGERS]
    receipts = [json.loads(p.read_text(encoding="utf-8"))
                for p in sorted(HISTORICAL_ADMISSIONS.glob("*/run-*/external-get-admission.json"))]
    known = tracked_assets(cohort, ledgers, receipts)
    baseline = json.loads(PGROONGA_WATCH_BASELINE.read_text(encoding="utf-8"),
                          object_pairs_hook=unique_json_pairs)
    known.setdefault("pgroonga/pgroonga", set()).update(
        reviewed_pgroonga_baseline(baseline, inventory))
    timescale = json.loads(TIMESCALEDB_WATCH_BASELINE.read_text(encoding="utf-8"),
                           object_pairs_hook=unique_json_pairs)
    known.setdefault("timescale/timescaledb", set()).update(
        reviewed_timescaledb_baseline(timescale, inventory))
    report = analyze(inventory, providers, known)
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Refuse overwrite of prior discovery output")
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"newStableCount": report["newStableCount"],
                      "baselineMissingCount": report["baselineMissingCount"],
                      "untrackedAssetProviderCount": report["untrackedAssetProviderCount"],
                      "trust": report["trust"], "downloadAuthorized": False}))
    import os
    with open(os.environ.get("GITHUB_STEP_SUMMARY", os.devnull), "a", encoding="utf-8") as f:
        f.write("## Daily external stable Release delta (metadata only)\n\n")
        f.write("| Provider | Latest stable release tag | Delta |\n|---|---|---|\n")
        for row in report["providers"]:
            f.write(f"| \`{row['repo']}\` | \`{row['latestTag'] or '-'}\` | {row['status']} |\n")
        f.write("\nUntrusted metadata; no downloads, admission or publication. "
                "See retained workflow artifact for exact asset-name deltas.\n")


if __name__ == "__main__":
    main()
