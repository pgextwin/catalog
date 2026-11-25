#!/usr/bin/env python3
"""Compare pre- and post-formalization Catalog trees and replay ledger admissions."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import cli_signed_feed
import compare_catalog_feeds
import identity_records
import package_ledger
import release_inventory


def _git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def _resolve_commit(repo: Path, ref: str) -> str:
    return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _read_json(path: Path) -> dict | list:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_dir_jsons(directory: Path) -> dict[str, dict]:
    if not directory.is_dir():
        return {}
    out: dict[str, dict] = {}
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix == ".json" and path.name != "index.candidate.json":
            out[path.stem] = _read_json(path)
    return out


def _dict_mismatches(left: dict, right: dict) -> dict:
    left_keys = set(left)
    right_keys = set(right)
    only_left = sorted(left_keys - right_keys)
    only_right = sorted(right_keys - left_keys)
    differing = sorted(k for k in (left_keys & right_keys) if left[k] != right[k])
    result: dict = {}
    if only_left:
        result["onlyInBefore"] = only_left
    if only_right:
        result["onlyInAfter"] = only_right
    if differing:
        result["differingKeys"] = differing
    return result


def _compare_maps(before_map: dict, after_map: dict, **extra: object) -> dict:
    equal = before_map == after_map
    out: dict = {"equal": equal}
    out.update(extra)
    if not equal:
        out.update(_dict_mismatches(before_map, after_map))
    return out


def _git_show_json(repo: Path, commit: str, rel_path: str) -> dict | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{rel_path}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return json.loads(proc.stdout)


def _snapshot_era_and_fingerprint(repo: Path, commit: str, name: str) -> dict | None:
    """Extract normalized admission-bearing content and era at (commit, name)."""
    pkg = _git_show_json(repo, commit, f"packages/{name}.json")
    ext = _git_show_json(repo, commit, f"extensions/{name}.json")
    idx = _git_show_json(repo, commit, "index.json")

    if pkg is not None:
        era = "identity-ledger-v3" if (isinstance(idx, dict) and idx.get("schemaVersion") == 3) else "ledger-v1"
        current = package_ledger.current_release(pkg)
        packages = {
            item["pgMajor"]: {
                "version": item.get("version"),
                "asset": item["asset"],
                "assetId": item.get("assetId"),
                "sha256": item["sha256"],
            }
            for item in current.get("packages", [])
        }
        licenses_by_major = {
            item["pgMajor"]: item.get("license")
            for item in current.get("packages", [])
            if "license" in item
        }
        return {
            "era": era,
            "releaseTag": current.get("releaseTag"),
            "releaseId": current.get("releaseId"),
            "packagingCommit": (pkg.get("capabilitiesSource") or {}).get("commit"),
            "packages": packages,
            "licensesByMajor": licenses_by_major,
            "topLicense": pkg.get("license"),
            "hasReleaseInventory": True,
            "isLedger": True,
        }

    if ext is not None:
        schema_ver = ext.get("schemaVersion")
        inv = ext.get("releaseInventory")
        has_inv = isinstance(inv, dict)
        if schema_ver == 1:
            era = "pre-ledger-v1"
        elif has_inv:
            era = "pre-ledger-v2-inventory"
        else:
            era = "pre-ledger-v2"
        latest = ext.get("latest") or {}
        release_tag = latest.get("releaseTag") or latest.get("tag")
        upstream = ext.get("upstream") or {}
        per_pg_upstream = upstream.get("perPostgresql") or {}
        inv_current = inv.get("current") if has_inv and isinstance(inv.get("current"), dict) else {}
        inv_licenses = (
            inv_current.get("licensesByMajor")
            if isinstance(inv_current.get("licensesByMajor"), dict)
            else {}
        )
        packages = {}
        licenses_by_major = {}
        for pg, info in (ext.get("postgresql") or {}).items():
            if not isinstance(info, dict) or not info.get("available"):
                continue
            version = (per_pg_upstream.get(pg) or {}).get("version", upstream.get("version"))
            packages[pg] = {
                "version": version,
                "asset": info.get("asset"),
                "assetId": None,
                "sha256": info.get("sha256"),
            }
            if pg in inv_licenses:
                licenses_by_major[pg] = inv_licenses[pg]
        return {
            "era": era,
            "releaseTag": release_tag,
            "releaseId": None,
            "packagingCommit": (ext.get("capabilitiesSource") or {}).get("commit"),
            "packages": packages,
            "licensesByMajor": licenses_by_major,
            "topLicense": ext.get("license"),
            "hasReleaseInventory": has_inv,
            "isLedger": False,
        }

    return None


def _core_packages(fp: dict) -> dict[str, tuple[str | None, str | None]]:
    return {
        pg: (pkg.get("asset"), pkg.get("sha256"))
        for pg, pkg in fp["packages"].items()
    }


def _versions_by_major(fp: dict) -> dict[str, str | None]:
    return {
        pg: pkg.get("version")
        for pg, pkg in fp["packages"].items()
    }


def _classify_commit_transition(prev_fp: dict | None, cur_fp: dict) -> str:
    """Classify a history commit as 'real' admission or 'format_only' refactor."""
    if prev_fp is None:
        return "real"

    if (
        prev_fp["releaseTag"] != cur_fp["releaseTag"]
        or _core_packages(prev_fp) != _core_packages(cur_fp)
        or prev_fp["topLicense"] != cur_fp["topLicense"]
    ):
        return "real"

    # v1 -> v2 added capabilitiesSource.commit without modifying the release itself.
    if prev_fp["packagingCommit"] is not None and cur_fp["packagingCommit"] != prev_fp["packagingCommit"]:
        return "real"
    if prev_fp["packagingCommit"] is None and cur_fp["packagingCommit"] is not None:
        if prev_fp["era"] != "pre-ledger-v1":
            return "real"

    # Both snapshots have per-major inventory licenses: license/version edits are admission-bearing.
    if prev_fp["hasReleaseInventory"] and cur_fp["hasReleaseInventory"]:
        if (
            prev_fp["licensesByMajor"] != cur_fp["licensesByMajor"]
            or _versions_by_major(prev_fp) != _versions_by_major(cur_fp)
        ):
            return "real"

    # Transitioning from pre-ledger files to a package ledger mints releaseId/assetId
    # and establishes the verifiable ledger admission commit for that extension.
    if not prev_fp["isLedger"] and cur_fp["isLedger"]:
        return "real"

    # Both snapshots are package ledgers: releaseId / assetId shifts are admission-bearing.
    if prev_fp["isLedger"] and cur_fp["isLedger"]:
        if prev_fp["releaseId"] != cur_fp["releaseId"]:
            return "real"
        prev_assets = {pg: pkg.get("assetId") for pg, pkg in prev_fp["packages"].items()}
        cur_assets = {pg: pkg.get("assetId") for pg, pkg in cur_fp["packages"].items()}
        if prev_assets != cur_assets:
            return "real"

    return "format_only"


def _extension_history(repo: Path, head_sha: str, name: str) -> list[dict]:
    """Walk first-parent history ending at head_sha and classify real vs format-only commits."""
    raw_commits = _git(
        repo,
        "log",
        "--first-parent",
        "--reverse",
        "--format=%H",
        head_sha,
        "--",
        f"packages/{name}.json",
        f"extensions/{name}.json",
    ).splitlines()
    commits = [line.strip() for line in raw_commits if line.strip()]
    if head_sha not in commits:
        head_fp = _snapshot_era_and_fingerprint(repo, head_sha, name)
        if head_fp is not None:
            commits.append(head_sha)

    entries: list[dict] = []
    prev_fp: dict | None = None
    for sha in commits:
        fp = _snapshot_era_and_fingerprint(repo, sha, name)
        if fp is None:
            continue
        kind = _classify_commit_transition(prev_fp, fp)
        content_changed = (
            prev_fp is None
            or prev_fp["releaseTag"] != fp["releaseTag"]
            or _core_packages(prev_fp) != _core_packages(fp)
        )
        entries.append({
            "commit": sha,
            "era": fp["era"],
            "kind": kind,
            "contentChanged": content_changed,
            "releaseTag": fp["releaseTag"],
        })
        prev_fp = fp
    return entries


def _latest_real_admission_commit(history: list[dict]) -> str | None:
    for entry in reversed(history):
        if entry["kind"] == "real":
            return entry["commit"]
    return history[-1]["commit"] if history else None


def _latest_content_origin_commit(history: list[dict]) -> str | None:
    for entry in reversed(history):
        if entry.get("contentChanged"):
            return entry["commit"]
    return history[-1]["commit"] if history else None


def _run_pages_build(wt: Path, out_dir: Path, effective_date: str) -> tuple[dict, dict[str, bytes]]:
    proc = subprocess.run(
        [
            sys.executable,
            str(wt / "scripts" / "build_pages.py"),
            "--inputs",
            str(wt / "site" / "inputs.json"),
            "--output",
            str(out_dir),
            "--date",
            effective_date,
        ],
        cwd=str(wt),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"build_pages.py failed in {wt} ({proc.returncode}): {proc.stderr or proc.stdout}"
        )
    summary = json.loads(proc.stdout)
    files: dict[str, bytes] = {}
    for path in sorted(out_dir.rglob("*")):
        if path.is_file():
            files[str(path.relative_to(out_dir))] = path.read_bytes()
    return summary, files


def _load_tree_state(wt: Path) -> dict:
    index_doc = _read_json(wt / "index.json")
    packages = _read_dir_jsons(wt / "packages")
    identities = _read_dir_jsons(wt / "identities")
    legacy_extensions = _read_dir_jsons(wt / "extensions")
    landscape_dir = wt / "landscape"
    landscape_extensions = _read_dir_jsons(landscape_dir / "extensions")
    landscape_index = (
        _read_json(landscape_dir / "index.json")
        if (landscape_dir / "index.json").is_file()
        else None
    )

    website_views = {
        name: package_ledger.website_record(ledger)
        for name, ledger in packages.items()
    }
    projected_landscape = {
        name: identity_records.project_landscape_v1(identity)
        for name, identity in identities.items()
    }
    external_files: dict[str, bytes] = {}
    ext_root = wt / "external"
    if ext_root.is_dir():
        for path in sorted(ext_root.rglob("*")):
            if path.is_file():
                external_files[str(path.relative_to(ext_root))] = path.read_bytes()

    return {
        "index": index_doc,
        "packages": packages,
        "identities": identities,
        "legacyExtensions": legacy_extensions,
        "landscapeExtensions": landscape_extensions,
        "landscapeIndex": landscape_index,
        "websiteViews": website_views,
        "projectedLandscape": projected_landscape,
        "externalFiles": external_files,
    }


def _pg_availability_map(state: dict, *, include_legacy: bool) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name, ledger in sorted(state["packages"].items()):
        current = package_ledger.current_release(ledger)
        website = state["websiteViews"][name]
        entry = {
            "unavailableMajors": ledger.get("unavailableMajors", []),
            "postgresql": website.get("postgresql", {}),
            "currentReleaseMajors": {
                item["pgMajor"]: {
                    "version": item.get("version"),
                    "asset": item["asset"],
                    "sha256": item["sha256"],
                }
                for item in current.get("packages", [])
            },
        }
        if include_legacy and name in state["legacyExtensions"]:
            legacy = state["legacyExtensions"][name]
            if legacy.get("postgresql") != website.get("postgresql"):
                entry["legacyPostgresqlMismatch"] = True
        out[name] = entry
    return out


def _packaging_evidence_map(state: dict, *, include_legacy: bool) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name, ledger in sorted(state["packages"].items()):
        website = state["websiteViews"][name]
        pg_evidence = {
            pg: info.get("evidence")
            for pg, info in sorted(website.get("postgresql", {}).items())
            if info.get("available")
        }
        release_ids = [
            {
                "releaseTag": rel["releaseTag"],
                "releaseId": rel["releaseId"],
                "assetIds": {pkg["pgMajor"]: pkg["assetId"] for pkg in rel.get("packages", [])},
            }
            for rel in ledger.get("releases", [])
        ]
        entry = {
            "repositoryId": ledger.get("repositoryId"),
            "latestReleaseId": ledger.get("latestReleaseId"),
            "checksumsAsset": website.get("latest", {}).get("checksumsAsset"),
            "runtime": ledger.get("runtime"),
            "capabilities": ledger.get("capabilities"),
            "capabilitiesSource": ledger.get("capabilitiesSource"),
            "perMajorEvidence": pg_evidence,
            "releaseIds": release_ids,
        }
        if include_legacy and name in state["legacyExtensions"]:
            legacy = state["legacyExtensions"][name]
            for key in ("runtime", "capabilities", "capabilitiesSource"):
                if legacy.get(key) != ledger.get(key):
                    entry[f"legacyMismatch_{key}"] = True
        out[name] = entry
    return out


def _per_major_licenses_map(state: dict, *, include_legacy: bool) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name, ledger in sorted(state["packages"].items()):
        identity = state["identities"].get(name, {})
        releases_licenses = []
        for rel in ledger.get("releases", []):
            majors = {}
            for item in rel.get("packages", []):
                majors[item["pgMajor"]] = release_inventory.license_for(item["license"])
            releases_licenses.append({
                "releaseTag": rel["releaseTag"],
                "majors": majors,
            })
        entry = {
            "topLicense": ledger.get("license"),
            "distributionIdentityLicense": identity.get("distribution", {}).get("license"),
            "researchIdentityLicense": identity.get("research", {}).get("license"),
            "releases": releases_licenses,
        }
        if include_legacy and name in state["legacyExtensions"]:
            if state["legacyExtensions"][name].get("license") != ledger.get("license"):
                entry["legacyTopLicenseMismatch"] = True
        out[name] = entry
    return out


def _distribution_views_comparison(before: dict, after: dict) -> dict:
    before_dist = before["legacyExtensions"] or before["websiteViews"]
    after_dist = after["websiteViews"]
    before_land = before["landscapeExtensions"] or before["projectedLandscape"]
    after_land = after["projectedLandscape"]

    identity_cross_checks = {}
    for name, website in sorted(after_dist.items()):
        identity = after["identities"].get(name, {})
        expected = {
            "name": identity.get("name"),
            "description": identity.get("description"),
            "upstreamRepository": identity.get("upstreamRepository"),
            "repository": identity.get("distribution", {}).get("repository"),
            "license": identity.get("distribution", {}).get("license"),
        }
        actual = {
            "name": website.get("name"),
            "description": website.get("description"),
            "upstreamRepository": website.get("upstream", {}).get("repository"),
            "repository": website.get("repository"),
            "license": website.get("license"),
        }
        if expected != actual:
            identity_cross_checks[name] = {"expected": expected, "actual": actual}

    land_index_mismatches = {}
    if isinstance(before["landscapeIndex"], dict):
        raw_entries = before["landscapeIndex"].get("extensions", [])
        if all(isinstance(entry, str) for entry in raw_entries):
            if sorted(raw_entries) != sorted(after_land):
                land_index_mismatches["roster"] = _dict_mismatches(
                    {k: True for k in raw_entries},
                    {k: True for k in after_land},
                )
        else:
            for entry in raw_entries:
                if not isinstance(entry, dict):
                    land_index_mismatches["invalidEntry"] = repr(entry)
                    continue
                name = entry.get("name")
                proj = after_land.get(name, {})
                for key in ("name", "displayName", "description", "upstreamRepository", "status"):
                    if entry.get(key) != proj.get(key):
                        land_index_mismatches.setdefault(name, {})[key] = {
                            "beforeIndex": entry.get(key),
                            "afterProjected": proj.get(key),
                        }

    dist_equal = before_dist == after_dist
    land_equal = before_land == after_land
    equal = dist_equal and land_equal and not identity_cross_checks and not land_index_mismatches
    result: dict = {
        "equal": equal,
        "distributedViewCount": len(after_dist),
        "landscapeViewCount": len(after_land),
        "distributedEqual": dist_equal,
        "landscapeEqual": land_equal,
    }
    if not dist_equal:
        result["distributedMismatches"] = _dict_mismatches(before_dist, after_dist)
    if not land_equal:
        result["landscapeMismatches"] = _dict_mismatches(before_land, after_land)
    if identity_cross_checks:
        result["identityCrossChecks"] = identity_cross_checks
    if land_index_mismatches:
        result["landscapeIndexMismatches"] = land_index_mismatches
    return result


def _descriptions_comparison(before: dict, after: dict) -> dict:
    before_dist_desc = {
        name: {
            "view": (before["legacyExtensions"].get(name) or before["websiteViews"][name]).get("description"),
            "ledger": before["packages"][name].get("description"),
            "identity": before["identities"].get(name, {}).get("description"),
        }
        for name in sorted(before["packages"])
    }
    after_dist_desc = {
        name: {
            "view": after["websiteViews"][name].get("description"),
            "ledger": after["packages"][name].get("description"),
            "identity": after["identities"].get(name, {}).get("description"),
        }
        for name in sorted(after["packages"])
    }
    before_land_desc = {
        name: (
            before["landscapeExtensions"][name]["description"]
            if name in before["landscapeExtensions"]
            else before["projectedLandscape"][name]["description"]
        )
        for name in sorted(before["identities"])
    }
    after_land_desc = {
        name: after["projectedLandscape"][name]["description"]
        for name in sorted(after["identities"])
    }
    override_ids = sorted(
        name
        for name, ident in after["identities"].items()
        if "descriptionOverride" in ident.get("research", {})
    )
    return {
        "equal": (
            before_dist_desc == after_dist_desc
            and before_land_desc == after_land_desc
            and all(
                len({v["view"], v["ledger"], v["identity"]}) == 1
                for v in after_dist_desc.values()
            )
        ),
        "distributedCount": len(after_dist_desc),
        "landscapeCount": len(after_land_desc),
        "descriptionOverrideIds": override_ids,
        "descriptionOverrideCount": len(override_ids),
        "distributedEqual": before_dist_desc == after_dist_desc,
        "landscapeEqual": before_land_desc == after_land_desc,
    }


def _research_blocks_comparison(before: dict, after: dict) -> dict:
    def _extract(state: dict) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for name, ident in sorted(state["identities"].items()):
            out[name] = {
                "name": ident.get("name"),
                "displayName": ident.get("displayName"),
                "upstreamRepository": ident.get("upstreamRepository"),
                "intake": ident.get("intake"),
                "distribution": ident.get("distribution"),
                "research": ident.get("research"),
            }
        return out

    before_research = _extract(before)
    after_research = _extract(after)
    index_research_only = sorted(
        item["name"]
        for item in after["index"].get("identities", [])
        if isinstance(item, dict) and item.get("intakeClass") == "research-only"
    )
    overlap_with_extensions = sorted(
        set(index_research_only) & set(after["index"].get("extensions", []))
    )
    equal = (before_research == after_research) and not overlap_with_extensions
    result = _compare_maps(
        before_research,
        after_research,
        identityCount=len(after_research),
        researchOnlyIds=index_research_only,
    )
    if overlap_with_extensions:
        result["equal"] = False
        result["researchOnlyInExtensions"] = overlap_with_extensions
    return result


def _external_routes_comparison(
    before: dict,
    after: dict,
    before_pages_summary: dict,
    after_pages_summary: dict,
) -> dict:
    before_files = {k: _sha256_bytes(v) for k, v in before["externalFiles"].items()}
    after_files = {k: _sha256_bytes(v) for k, v in after["externalFiles"].items()}
    before_refs = {
        name: (before["landscapeExtensions"].get(name) or before["projectedLandscape"][name]).get("externalSourceRegistry")
        for name in sorted(before["identities"])
    }
    after_refs = {
        name: after["identities"][name].get("research", {}).get("externalSourceRegistry")
        for name in sorted(after["identities"])
    }
    before_dist_refs = {
        name: (before["legacyExtensions"].get(name) or before["websiteViews"][name]).get("externalSourceRegistry")
        for name in sorted(before["packages"])
    }
    after_dist_refs = {
        name: after["identities"].get(name, {}).get("distribution", {}).get("externalSourceRegistry")
        for name in sorted(after["packages"])
    }
    after_dist_view_refs = {
        name: after["websiteViews"][name].get("externalSourceRegistry")
        for name in sorted(after["packages"])
    }
    before_counts = {
        "externalDirectRecords": before_pages_summary["counts"].get("externalDirectRecords"),
        "externalStandaloneRecords": before_pages_summary["counts"].get("externalStandaloneRecords"),
    }
    after_counts = {
        "externalDirectRecords": after_pages_summary["counts"].get("externalDirectRecords"),
        "externalStandaloneRecords": after_pages_summary["counts"].get("externalStandaloneRecords"),
    }
    references_equal = (
        before_refs == after_refs
        and before_dist_refs == after_dist_refs
        and after_dist_refs == after_dist_view_refs
    )
    equal = (
        before_files == after_files
        and references_equal
        and before_counts == after_counts
    )
    out: dict = {
        "equal": equal,
        "externalFileCount": len(after_files),
        "externalCounts": after_counts,
        "filesEqual": before_files == after_files,
        "referencesEqual": references_equal,
        "countsEqual": before_counts == after_counts,
    }
    if before_files != after_files:
        out["fileMismatches"] = _dict_mismatches(before_files, after_files)
    if before_refs != after_refs:
        out["referenceMismatches"] = _dict_mismatches(before_refs, after_refs)
    if before_dist_refs != after_dist_refs or after_dist_refs != after_dist_view_refs:
        out["distributedReferenceMismatches"] = {
            "beforeVsAfterIdentity": _dict_mismatches(before_dist_refs, after_dist_refs),
            "afterIdentityVsWebsiteView": _dict_mismatches(after_dist_refs, after_dist_view_refs),
        }
    return out


def _extract_card_ids(html_text: str, *, class_name: str, prefix: str) -> list[str]:
    pattern = re.compile(
        rf'<details\b[^>]*class="[^"]*\b{re.escape(class_name)}\b[^"]*"[^>]*id="{re.escape(prefix)}([^"]+)"'
    )
    return sorted(pattern.findall(html_text))


def _rendered_site_comparison(
    before_wt: Path,
    before_sha: str,
    before_summary: dict,
    before_files: dict[str, bytes],
    after_wt: Path,
    after_sha: str,
    after_summary: dict,
    after_files: dict[str, bytes],
    after_state: dict,
) -> dict:
    counts_equal = before_summary.get("counts") == after_summary.get("counts")
    before_filters = before_summary.get("filtersFile")
    after_filters = after_summary.get("filtersFile")

    before_inputs_raw = (before_wt / "site" / "inputs.json").read_bytes()
    after_inputs_raw = (after_wt / "site" / "inputs.json").read_bytes()
    before_inputs_sha = _sha256_bytes(before_inputs_raw)
    after_inputs_sha = _sha256_bytes(after_inputs_raw)
    before_inputs_norm = json.loads(before_inputs_raw.decode("utf-8"))
    after_inputs_norm = json.loads(after_inputs_raw.decode("utf-8"))
    if isinstance(before_inputs_norm.get("catalogPaths"), dict):
        before_inputs_norm["catalogPaths"].pop("identitiesIndex", None)
    if isinstance(after_inputs_norm.get("catalogPaths"), dict):
        after_inputs_norm["catalogPaths"].pop("identitiesIndex", None)
    inputs_equivalent = before_inputs_norm == after_inputs_norm

    def _norm_key(rel: str, filters_name: str | None) -> str:
        return "__FILTERS_FILE__" if filters_name and rel == filters_name else rel

    def _norm_bytes(data: bytes, sha: str, filters_name: str | None) -> bytes:
        text_bytes = data.replace(sha.encode("utf-8"), b"__CATALOG_COMMIT__")
        if filters_name:
            text_bytes = text_bytes.replace(filters_name.encode("utf-8"), b"__FILTERS_FILE__")
        return text_bytes

    left_map = {
        _norm_key(rel, before_filters): _norm_bytes(raw, before_sha, before_filters)
        for rel, raw in before_files.items()
    }
    right_map = {
        _norm_key(rel, after_filters): _norm_bytes(raw, after_sha, after_filters)
        for rel, raw in after_files.items()
    }

    filters_content_equal = False
    if "__FILTERS_FILE__" in left_map and "__FILTERS_FILE__" in right_map:
        left_f = json.loads(left_map["__FILTERS_FILE__"].decode("utf-8"))
        right_f = json.loads(right_map["__FILTERS_FILE__"].decode("utf-8"))
        filters_content_equal = left_f == right_f

    before_ext_en = _extract_card_ids(
        before_files.get("en/index.html", b"").decode("utf-8", errors="replace"),
        class_name="extension-collapse",
        prefix="extension-",
    )
    before_ext_ja = _extract_card_ids(
        before_files.get("ja/index.html", b"").decode("utf-8", errors="replace"),
        class_name="extension-collapse",
        prefix="extension-",
    )
    after_ext_en = _extract_card_ids(
        after_files.get("en/index.html", b"").decode("utf-8", errors="replace"),
        class_name="extension-collapse",
        prefix="extension-",
    )
    after_ext_ja = _extract_card_ids(
        after_files.get("ja/index.html", b"").decode("utf-8", errors="replace"),
        class_name="extension-collapse",
        prefix="extension-",
    )
    before_land_en = _extract_card_ids(
        before_files.get("en/index.html", b"").decode("utf-8", errors="replace"),
        class_name="landscape-collapse",
        prefix="landscape-",
    )
    before_land_ja = _extract_card_ids(
        before_files.get("ja/index.html", b"").decode("utf-8", errors="replace"),
        class_name="landscape-collapse",
        prefix="landscape-",
    )
    after_land_en = _extract_card_ids(
        after_files.get("en/index.html", b"").decode("utf-8", errors="replace"),
        class_name="landscape-collapse",
        prefix="landscape-",
    )
    after_land_ja = _extract_card_ids(
        after_files.get("ja/index.html", b"").decode("utf-8", errors="replace"),
        class_name="landscape-collapse",
        prefix="landscape-",
    )
    rendered_registry_ids = sorted(after_state["identities"])
    rendered_ids_equal = (
        before_ext_en == before_ext_ja == after_ext_en == after_ext_ja
        and before_land_en == before_land_ja == after_land_en == after_land_ja
        and len(after_ext_en) == after_summary.get("counts", {}).get("distributedExtensions")
        and len(rendered_registry_ids) == after_summary.get("counts", {}).get("landscapeRegistry")
        and len(after_land_en) == after_summary.get("counts", {}).get("landscapeDisplayed")
    )

    def _normalize_manifest(
        files_map: dict[str, bytes],
        sha: str,
        filters_name: str | None,
        inputs_sha: str,
    ) -> tuple[dict | None, bool]:
        if "manifest.json" not in files_map:
            return None, False
        doc = json.loads(files_map["manifest.json"].decode("utf-8"))
        if doc.get("inputsSha256") != inputs_sha:
            return doc, False
        # Verify manifest self-hashes before normalizing commit-derived hashes.
        manifest_files = doc.get("files") if isinstance(doc.get("files"), dict) else {}
        for rel, meta in manifest_files.items():
            raw = files_map.get(rel)
            if raw is None or not isinstance(meta, dict):
                return doc, False
            if meta.get("bytes") != len(raw) or meta.get("sha256") != _sha256_bytes(raw):
                return doc, False

        normalized = copy.deepcopy(doc)
        if normalized.get("catalogCommit") == sha:
            normalized["catalogCommit"] = "__CATALOG_COMMIT__"
        normalized["inputsSha256"] = "__INPUTS_SHA256__"
        if filters_name and normalized.get("filtersFile") == filters_name:
            normalized["filtersFile"] = "__FILTERS_FILE__"
        norm_files = normalized.get("files")
        if isinstance(norm_files, dict):
            remapped = {}
            commit_bound = {filters_name, "en/index.html", "ja/index.html"}
            for rel, meta in norm_files.items():
                key = "__FILTERS_FILE__" if filters_name and rel == filters_name else rel
                entry = copy.deepcopy(meta)
                if rel in commit_bound:
                    entry["sha256"] = "__COMMIT_DEPENDENT_SHA256__"
                remapped[key] = entry
            normalized["files"] = remapped
        return normalized, True

    left_manifest, left_manifest_valid = _normalize_manifest(
        before_files, before_sha, before_filters, before_inputs_sha
    )
    right_manifest, right_manifest_valid = _normalize_manifest(
        after_files, after_sha, after_filters, after_inputs_sha
    )
    manifest_equal = (
        left_manifest_valid
        and right_manifest_valid
        and inputs_equivalent
        and left_manifest is not None
        and left_manifest == right_manifest
    )
    commits_match = (
        before_summary.get("catalogCommit") == before_sha
        and after_summary.get("catalogCommit") == after_sha
    )
    all_paths = sorted(set(left_map) | set(right_map))
    mismatched_files = [
        rel
        for rel in all_paths
        if (
            rel == "manifest.json" and not manifest_equal
        ) or (
            rel != "manifest.json"
            and (rel not in left_map or rel not in right_map or left_map[rel] != right_map[rel])
        )
    ]

    equal = (
        counts_equal
        and rendered_ids_equal
        and commits_match
        and inputs_equivalent
        and not mismatched_files
        and manifest_equal
        and filters_content_equal
    )
    return {
        "equal": equal,
        "countsEqual": counts_equal,
        "renderedIdsEqual": rendered_ids_equal,
        "catalogCommitsMatch": commits_match,
        "inputsEquivalent": inputs_equivalent,
        "filtersContentEqual": filters_content_equal,
        "manifestNonCommitFieldsEqual": manifest_equal,
        "beforeFiltersFile": before_filters,
        "afterFiltersFile": after_filters,
        "beforeCounts": before_summary.get("counts"),
        "afterCounts": after_summary.get("counts"),
        "renderedDistributedIds": after_ext_en,
        "renderedLandscapeRegistryIds": rendered_registry_ids,
        "renderedLandscapeDisplayedIds": after_land_en,
        "fileCount": len(after_files),
        "mismatchedFiles": mismatched_files,
    }


def _publication_noop_comparison(
    before_wt: Path,
    after_wt: Path,
    feed_equal: bool,
) -> dict:
    before_names = cli_signed_feed.catalog_names(before_wt, package_ledger.DIRECTORY)
    after_names = cli_signed_feed.catalog_names(after_wt, package_ledger.DIRECTORY)
    legacy_names = (
        cli_signed_feed.catalog_names(before_wt, "extensions")
        if (before_wt / "extensions").is_dir()
        else before_names
    )
    publication_decision = "noop" if feed_equal else "changed"
    equal = feed_equal and before_names == after_names and legacy_names == after_names
    return {
        "equal": equal,
        "verdict": "equal" if equal else "diff",
        "publicationDecision": publication_decision,
        "beforeCatalogNamesCount": len(before_names),
        "afterCatalogNamesCount": len(after_names),
        "catalogNamesMatch": before_names == after_names and legacy_names == after_names,
    }


def build_migration_diff(
    before_wt: Path,
    before_sha: str,
    after_wt: Path,
    after_sha: str,
    effective_date: str,
) -> tuple[dict, dict, dict]:
    """Compare all 11 semantic and rendered categories across before and after worktrees."""
    before_state = _load_tree_state(before_wt)
    after_state = _load_tree_state(after_wt)

    feed_equal, raw_sha_a, raw_sha_b, norm_sha_a, norm_sha_b = compare_catalog_feeds.compare(
        before_wt,
        before_sha,
        after_wt,
        after_sha,
    )
    feed_after = cli_signed_feed.build_feed(after_wt, after_sha)
    normalized_feed = {
        "equal": feed_equal,
        "beforeNormalizedSha256": norm_sha_a,
        "afterNormalizedSha256": norm_sha_b,
        "beforeRawSha256": raw_sha_a,
        "afterRawSha256": raw_sha_b,
        "extensionCount": len(feed_after.get("extensions", {})),
    }
    noop_verdict = _publication_noop_comparison(before_wt, after_wt, feed_equal)

    with tempfile.TemporaryDirectory(prefix="catalog-pages-diff-") as pages_tmp:
        pages_dir = Path(pages_tmp)
        before_summary, before_files = _run_pages_build(
            before_wt, pages_dir / "before", effective_date
        )
        after_summary, after_files = _run_pages_build(
            after_wt, pages_dir / "after", effective_date
        )

    ledger_cmp = _compare_maps(
        before_state["packages"],
        after_state["packages"],
        ledgerCount=len(after_state["packages"]),
        indexExtensionsMatchPackages=(
            sorted(after_state["packages"]) == sorted(after_state["index"].get("extensions", []))
        ),
    )
    if not ledger_cmp["indexExtensionsMatchPackages"]:
        ledger_cmp["equal"] = False

    pg_cmp = _compare_maps(
        _pg_availability_map(before_state, include_legacy=True),
        _pg_availability_map(after_state, include_legacy=False),
        extensionCount=len(after_state["packages"]),
    )
    ev_cmp = _compare_maps(
        _packaging_evidence_map(before_state, include_legacy=True),
        _packaging_evidence_map(after_state, include_legacy=False),
        extensionCount=len(after_state["packages"]),
    )
    lic_cmp = _compare_maps(
        _per_major_licenses_map(before_state, include_legacy=True),
        _per_major_licenses_map(after_state, include_legacy=False),
        extensionCount=len(after_state["packages"]),
    )
    views_cmp = _distribution_views_comparison(before_state, after_state)
    desc_cmp = _descriptions_comparison(before_state, after_state)
    research_cmp = _research_blocks_comparison(before_state, after_state)
    external_cmp = _external_routes_comparison(
        before_state, after_state, before_summary, after_summary
    )
    site_cmp = _rendered_site_comparison(
        before_wt,
        before_sha,
        before_summary,
        before_files,
        after_wt,
        after_sha,
        after_summary,
        after_files,
        after_state,
    )

    categories = {
        "normalized_signed_feed": normalized_feed,
        "publication_noop_verdict": noop_verdict,
        "ledger_releases": ledger_cmp,
        "postgresql_versions_and_availability": pg_cmp,
        "packaging_and_signing_evidence": ev_cmp,
        "per_major_licenses": lic_cmp,
        "distribution_views_vs_identity_derived": views_cmp,
        "descriptions_both_sets": desc_cmp,
        "research_blocks": research_cmp,
        "external_routes": external_cmp,
        "rendered_site_and_counts": site_cmp,
    }
    for cat in categories.values():
        cat["verdict"] = "equal" if bool(cat["equal"]) else "diff"
    verdict = "equal" if all(bool(item["equal"]) for item in categories.values()) else "diff"
    diff_doc = {
        "schema": "catalog-c-migration-diff-v1",
        "beforeCommit": before_sha,
        "afterCommit": after_sha,
        "verdict": verdict,
        "categories": categories,
    }
    return diff_doc, before_state, after_state


def _bump_synthetic_release(
    ledger: dict,
    *,
    tag_suffix: str,
    version: str,
    id_delta: int,
    sha_char: str,
) -> dict:
    cur = package_ledger.current_release(ledger)
    new_rel = copy.deepcopy(cur)
    name = ledger["name"]
    repo = ledger["repository"]
    new_tag = f"v{version}-windows.{tag_suffix}"
    new_rel["releaseTag"] = new_tag
    new_rel["releaseId"] = cur["releaseId"] + id_delta
    new_rel["publishedAt"] = f"2026-11-26T0{id_delta}:00:00Z"
    for pkg in new_rel["packages"]:
        pg = pkg["pgMajor"]
        asset = f"{name}-{version}-pg{pg}-windows-x64.zip"
        pkg["version"] = version
        pkg["asset"] = asset
        pkg["assetId"] = pkg["assetId"] + id_delta * 10
        pkg["sha256"] = sha_char * 64
        if "downloadUrl" in pkg:
            pkg["downloadUrl"] = f"https://github.com/{repo}/releases/download/{new_tag}/{asset}"
        evidence = pkg.get("evidence") or {}
        for ev_key in ("sbom", "vulnerabilityReport"):
            ev = evidence.get(ev_key)
            if isinstance(ev, dict) and ev.get("available"):
                ext_suffix = ".spdx.json" if ev_key == "sbom" else ".vulnerabilities.json"
                ev_asset = f"{name}-{version}-pg{pg}-windows-x64{ext_suffix}"
                ev["asset"] = ev_asset
                ev["downloadUrl"] = f"https://github.com/{repo}/releases/download/{new_tag}/{ev_asset}"
                ev["sha256"] = sha_char * 64
    return new_rel


def _commit_scratch_file(
    scratch_repo: Path,
    rel_path: str,
    content: bytes,
    message: str,
) -> str:
    target = scratch_repo / rel_path
    target.write_bytes(content)
    _git(scratch_repo, "add", rel_path)
    _git(scratch_repo, "commit", "-m", message)
    sha = _resolve_commit(scratch_repo, "HEAD")
    _git(scratch_repo, "update-ref", "refs/remotes/origin/main", sha)
    return sha


def _run_scratch_subsequent_exercises(
    repo: Path,
    after_sha: str,
    extension_names: list[str],
    initial_latest_real: dict[str, str],
) -> dict:
    """Exercise subsequent v3 release updates and format-only commits in a disposable clone."""
    targets = [n for n in ("pg_repack", "pg_hint_plan") if n in extension_names]
    if not targets:
        targets = extension_names[:2]
    if not targets:
        return {"passed": False, "error": "No distributed extensions available"}

    with tempfile.TemporaryDirectory(prefix="catalog-scratch-clone-") as tmp:
        scratch_repo = Path(tmp) / "repo"
        proc = subprocess.run(
            ["git", "clone", "--no-hardlinks", str(repo), str(scratch_repo)],
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {proc.stderr.strip()}")
        _git(scratch_repo, "fetch", str(repo), after_sha)
        _git(scratch_repo, "checkout", "-B", "main", "FETCH_HEAD")
        _git(scratch_repo, "update-ref", "refs/remotes/origin/main", after_sha)
        _git(scratch_repo, "config", "user.name", "Migration Verify Bot")
        _git(scratch_repo, "config", "user.email", "verify@example.invalid")

        # Exercise A: real release updates after v3 formalization using superseded_releases.
        exercise_a: dict[str, dict] = {}
        for idx, ext in enumerate(targets, start=1):
            ledger = package_ledger.read_record(scratch_repo / "packages" / f"{ext}.json")
            prev_real = initial_latest_real[ext]
            new_rel = _bump_synthetic_release(
                ledger,
                tag_suffix="1",
                version=f"99.{idx}.0",
                id_delta=100 * idx,
                sha_char="a",
            )
            retired = package_ledger.superseded_releases(
                ledger, new_rel, lambda c=prev_real: c
            )
            updated = package_ledger.ledger_record(
                package_ledger.website_record(ledger),
                ledger["repositoryId"],
                new_rel,
                retired,
            )
            commit_a = _commit_scratch_file(
                scratch_repo,
                f"packages/{ext}.json",
                package_ledger.json_bytes(updated),
                f"test: subsequent v3 admission for {ext}",
            )
            load_adm = package_ledger.git_admissions(scratch_repo)
            feed = cli_signed_feed.build_feed(
                scratch_repo, commit_a, load_admission=load_adm
            )
            retired_pins = [
                {
                    "releaseTag": rel["releaseTag"],
                    "catalogCommit": rel["admission"]["catalogCommit"],
                }
                for rel in updated["releases"]
                if "admission" in rel
            ]
            for rel in updated["releases"]:
                if "admission" in rel:
                    cli_signed_feed.verify_ledger_admission(
                        ext, updated["repositoryId"], rel, load_adm
                    )
            feed_by_ext = {item["extension"]: item for item in feed.get("extensions", [])}
            exercise_a[ext] = {
                "passed": (
                    ext in feed_by_ext
                    and feed_by_ext[ext].get("latestReleaseTag") == new_rel["releaseTag"]
                ),
                "commit": commit_a,
                "previousRealCommitStamped": prev_real,
                "retiredVerifiedCount": len(retired_pins),
                "retiredPins": retired_pins,
            }

        primary = targets[0]
        primary_a_commit = exercise_a[primary]["commit"]

        # Exercise B: format-only commit must be skipped by semantic resolver unlike naive git log -1.
        pkg_path = scratch_repo / "packages" / f"{primary}.json"
        pkg_obj = _read_json(pkg_path)
        formatted_bytes = (json.dumps(pkg_obj, indent=4) + "\n").encode("utf-8")
        format_commit = _commit_scratch_file(
            scratch_repo,
            f"packages/{primary}.json",
            formatted_bytes,
            f"chore: format-only reindent on {primary}",
        )
        naive_head = _git(
            scratch_repo,
            "log",
            "-1",
            "--format=%H",
            format_commit,
            "--",
            f"packages/{primary}.json",
            f"extensions/{primary}.json",
        ).strip()
        history_b = _extension_history(scratch_repo, format_commit, primary)
        resolved_b = _latest_real_admission_commit(history_b)
        exercise_b = {
            "passed": naive_head == format_commit and resolved_b == primary_a_commit,
            "extension": primary,
            "formatOnlyCommit": format_commit,
            "naiveGitLogLatest": naive_head,
            "semanticResolvedLatestReal": resolved_b,
            "expectedRealCommit": primary_a_commit,
        }

        # Exercise C: second real update retires the first v3 update cleanly using resolved commit.
        ledger_b = package_ledger.read_record(pkg_path)
        new_rel_2 = _bump_synthetic_release(
            ledger_b,
            tag_suffix="2",
            version="99.9.0",
            id_delta=500,
            sha_char="b",
        )
        retired_c = package_ledger.superseded_releases(
            ledger_b, new_rel_2, lambda c=resolved_b: c
        )
        updated_c = package_ledger.ledger_record(
            package_ledger.website_record(ledger_b),
            ledger_b["repositoryId"],
            new_rel_2,
            retired_c,
        )
        commit_c = _commit_scratch_file(
            scratch_repo,
            f"packages/{primary}.json",
            package_ledger.json_bytes(updated_c),
            f"test: second v3 admission retiring v99.1.0 for {primary}",
        )
        load_adm_c = package_ledger.git_admissions(scratch_repo)
        feed_c = cli_signed_feed.build_feed(
            scratch_repo, commit_c, load_admission=load_adm_c
        )
        retired_c_tags = []
        for rel in updated_c["releases"]:
            if "admission" in rel:
                cli_signed_feed.verify_ledger_admission(
                    primary, updated_c["repositoryId"], rel, load_adm_c
                )
                retired_c_tags.append({
                    "releaseTag": rel["releaseTag"],
                    "catalogCommit": rel["admission"]["catalogCommit"],
                })
        first_v3_pin_verified = any(
            item["releaseTag"] == "v99.1.0-windows.1" and item["catalogCommit"] == primary_a_commit
            for item in retired_c_tags
        )
        feed_c_by_ext = {item["extension"]: item for item in feed_c.get("extensions", [])}
        exercise_c = {
            "passed": (
                first_v3_pin_verified
                and primary in feed_c_by_ext
                and feed_c_by_ext[primary].get("latestReleaseTag") == new_rel_2["releaseTag"]
            ),
            "extension": primary,
            "commit": commit_c,
            "retiredPinsVerified": retired_c_tags,
            "firstV3ReleasePinVerified": first_v3_pin_verified,
        }

    overall = (
        all(item["passed"] for item in exercise_a.values())
        and exercise_b["passed"]
        and exercise_c["passed"]
    )
    return {
        "passed": overall,
        "exerciseA_realUpdates": exercise_a,
        "exerciseB_formatOnlySkipped": exercise_b,
        "exerciseC_secondUpdateRetiresFirstV3": exercise_c,
    }


def build_admission_replay(
    repo: Path,
    after_wt: Path,
    after_sha: str,
    after_state: dict,
) -> dict:
    """Replay historical admissions across eras and verify scratch subsequent updates."""
    extension_names = sorted(after_state["packages"])
    histories: dict[str, dict] = {}
    latest_real_commits: dict[str, str] = {}
    historical_pins_verified = 0
    historical_errors: list[str] = []

    load_adm = package_ledger.git_admissions(after_wt)
    # Build live feed at after_sha directly to verify all embedded retired admissions.
    cli_signed_feed.build_feed(after_wt, after_sha, load_admission=load_adm)

    for name in extension_names:
        history = _extension_history(repo, after_sha, name)
        latest_real = _latest_real_admission_commit(history)
        if latest_real is None:
            historical_errors.append(f"{name}: empty first-parent history")
            continue
        latest_real_commits[name] = latest_real
        if latest_real == after_sha and any(e["kind"] == "format_only" for e in history):
            # Only fail if an earlier commit already existed and after_sha is pure migration.
            if len(history) > 1 and history[-1]["kind"] == "format_only":
                historical_errors.append(
                    f"{name}: migration commit {after_sha} misclassified as latest real admission"
                )

        ledger = after_state["packages"][name]
        verified_releases: list[dict] = []
        for rel in ledger.get("releases", []):
            if "admission" in rel:
                try:
                    cli_signed_feed.verify_ledger_admission(
                        name, ledger["repositoryId"], rel, load_adm
                    )
                    historical_pins_verified += 1
                    verified_releases.append({
                        "releaseTag": rel["releaseTag"],
                        "catalogCommit": rel["admission"]["catalogCommit"],
                        "verified": True,
                    })
                except Exception as exc:
                    historical_errors.append(f"{name}@{rel['releaseTag']}: {exc}")
                    verified_releases.append({
                        "releaseTag": rel["releaseTag"],
                        "catalogCommit": rel["admission"].get("catalogCommit"),
                        "verified": False,
                        "error": str(exc),
                    })

        # Verify current live release also pins cleanly against the semantic latestRealAdmissionCommit
        # when that commit already exists in ledger-v1 / pre-ledger-v2-inventory era.
        latest_rel = package_ledger.current_release(ledger)
        latest_with_adm = copy.deepcopy(latest_rel)
        latest_with_adm["admission"] = {"catalogCommit": latest_real}
        try:
            cli_signed_feed.verify_ledger_admission(
                name, ledger["repositoryId"], latest_with_adm, load_adm
            )
            latest_verified = True
        except Exception as exc:
            latest_verified = False
            historical_errors.append(f"{name} latest@{latest_real}: {exc}")

        real_count = sum(1 for item in history if item["kind"] == "real")
        fmt_count = sum(1 for item in history if item["kind"] == "format_only")
        eras_seen = []
        for item in history:
            if item["era"] not in eras_seen:
                eras_seen.append(item["era"])
        histories[name] = {
            "latestRealAdmissionCommit": latest_real,
            "latestContentOriginCommit": _latest_content_origin_commit(history),
            "latestVerifiedAtRealCommit": latest_verified,
            "commitCount": len(history),
            "realAdmissionCount": real_count,
            "formatOnlyCount": fmt_count,
            "erasSeen": eras_seen,
            "retiredPinsVerified": verified_releases,
            "commits": history,
        }

    scratch_results = _run_scratch_subsequent_exercises(
        repo, after_sha, extension_names, latest_real_commits
    )
    misclassified_after = [
        name
        for name, item in histories.items()
        if item["latestRealAdmissionCommit"] == after_sha
        and item["commitCount"] > 1
        and item["commits"][-1]["kind"] == "format_only"
    ]
    pins_ok = (
        len(histories) == len(extension_names)
        and all(item["latestVerifiedAtRealCommit"] for item in histories.values())
        and all(
            all(pin.get("verified") for pin in item["retiredPinsVerified"])
            for item in histories.values()
        )
        and not historical_errors
    )
    era_walk_ok = (
        len(histories) == len(extension_names)
        and all(item["commitCount"] >= 1 for item in histories.values())
        and not misclassified_after
    )
    subsequent_ok = bool(scratch_results.get("passed"))
    replay_categories = {
        "historical_pins_replay": {
            "verdict": "pass" if pins_ok else "fail",
            "extensionCount": len(extension_names),
            "historicalPinsVerified": historical_pins_verified,
            "errorCount": len(historical_errors),
        },
        "era_walk_and_format_only_guard": {
            "verdict": "pass" if era_walk_ok else "fail",
            "extensionCount": len(histories),
            "misclassifiedMigrationCommitExtensions": misclassified_after,
        },
        "first_subsequent_update_exercises": {
            "verdict": "pass" if subsequent_ok else "fail",
            "exerciseCount": 3,
        },
    }
    verdict = "pass" if (pins_ok and era_walk_ok and subsequent_ok) else "fail"
    return {
        "schema": "catalog-c-admission-replay-v1",
        "afterCommit": after_sha,
        "verdict": verdict,
        "categories": replay_categories,
        "extensionCount": len(extension_names),
        "historicalPinsVerified": historical_pins_verified,
        "historicalErrors": historical_errors,
        "extensions": histories,
        "subsequentUpdateExercises": scratch_results,
    }


def compare_migration(
    repo: Path,
    before_ref: str,
    after_ref: str,
    output_dir: Path,
    effective_date: str = "2026-11-25",
) -> tuple[dict, dict, int]:
    """Compare before/after catalog commits and write migration evidence JSON artifacts."""
    before_sha = _resolve_commit(repo, before_ref)
    after_sha = _resolve_commit(repo, after_ref)
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="catalog-migration-wt-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        before_wt = tmp_path / "before"
        after_wt = tmp_path / "after"
        try:
            _git(repo, "worktree", "add", "--detach", str(before_wt), before_sha)
            _git(repo, "worktree", "add", "--detach", str(after_wt), after_sha)

            diff_doc, _, after_state = build_migration_diff(
                before_wt, before_sha, after_wt, after_sha, effective_date
            )
            replay_doc = build_admission_replay(repo, after_wt, after_sha, after_state)
        finally:
            for wt in (before_wt, after_wt):
                if wt.exists():
                    subprocess.run(
                        ["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    shutil.rmtree(wt, ignore_errors=True)
            subprocess.run(
                ["git", "-C", str(repo), "worktree", "prune"],
                capture_output=True,
                text=True,
                check=False,
            )

    (output_dir / "catalog-c-migration-diff.json").write_text(
        json.dumps(diff_doc, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    (output_dir / "catalog-c-admission-replay.json").write_text(
        json.dumps(replay_doc, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    ok = diff_doc["verdict"] == "equal" and replay_doc["verdict"] == "pass"
    return diff_doc, replay_doc, (0 if ok else 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, help="Pre-migration commit SHA or ref")
    parser.add_argument("--after", required=True, help="Post-migration commit SHA or ref")
    parser.add_argument("--output", required=True, help="Directory for evidence JSON artifacts")
    parser.add_argument(
        "--repo",
        default=str(SCRIPT_DIR.parent),
        help="Git repository path (defaults to repo root)",
    )
    parser.add_argument(
        "--date",
        default="2026-11-25",
        help="Effective UTC date passed to build_pages.py (YYYY-MM-DD)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        print(json.dumps({"status": "ERROR", "error": f"Not a git repository: {repo}"}), file=sys.stderr)
        return 2

    try:
        diff_doc, replay_doc, code = compare_migration(
            repo,
            args.before,
            args.after,
            Path(args.output).resolve(),
            effective_date=args.date,
        )
    except Exception as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "status": "OK" if code == 0 else "DIFF",
                "beforeCommit": diff_doc["beforeCommit"],
                "afterCommit": diff_doc["afterCommit"],
                "diffVerdict": diff_doc["verdict"],
                "replayVerdict": replay_doc["verdict"],
                "historicalPinsVerified": replay_doc["historicalPinsVerified"],
                "outputDir": str(Path(args.output).resolve()),
            }
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
