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
        newer = not historical_tags or tag_key(release["tag"]) > max(historical_tags)
        status = ("NEW_STABLE_RELEASE" if new and newer else
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
            "untrackedAssetProviderCount": sum(
                r["status"] == "UNTRACKED_ASSET_IN_KNOWN_VERSION" for r in rows)}


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
    report = analyze(inventory, providers, tracked_assets(cohort, ledgers, receipts))
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Refuse overwrite of prior discovery output")
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"newStableCount": report["newStableCount"],
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
