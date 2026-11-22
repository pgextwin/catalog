#!/usr/bin/env python3
"""Pure, fail-closed Catalog v2 mapping for independently verified signed public Releases.

Does not download artifacts, verify GitHub attestations, dispatch workflows,
merge PRs or publish Releases. Call ONLY after a separate fully signed Release
verifier has checked actual remote asset bytes and provenance.
"""
from __future__ import annotations
from collections import Counter
import copy
import json
from pathlib import Path
import re

if __package__:
    from . import package_ledger
    from .release_inventory import license_for, license_pins, match_zip, release_assets, version_for
else:
    import package_ledger
    from release_inventory import license_for, license_pins, match_zip, release_assets, version_for


ALLOWED = {
    "pg_bigm": "pgbigm/pg_bigm",
    "pg_cron": "citusdata/pg_cron",
    "pg_hint_plan": "ossc-db/pg_hint_plan",
    "pgaudit": "pgaudit/pgaudit",
    "set_user": "pgaudit/set_user",
    "pg_repack": "reorg/pg_repack",
    "pg_ivm": "sraoss/pg_ivm",
    "pg_qualstats": "powa-team/pg_qualstats",
    "plpgsql_check": "okbob/plpgsql_check",
    "hypopg": "HypoPG/hypopg",
    "wal2json": "eulerto/wal2json",
    "pg_partman": "pgpartman/pg_partman",
    "pg_stat_monitor": "percona/pg_stat_monitor",
    "orafce": "orafce/orafce",
}

# First-Release identities are admitted only from protected Catalog metadata.
# This manifest is NOT Publisher permission or independent signature evidence.
SEALED_FIRST_RELEASE_UPSTREAM = {
    "pgtap": "theory/pgtap",
    "pg_variables": "postgrespro/pg_variables",
    "pg_store_plans": "ossc-db/pg_store_plans",
}
_NEW_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_NEW_UPSTREAM = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


def load_first_release_registry(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 65536:
        raise ValueError("missing or oversized protected first-Release manifest")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate protected first-Release manifest field")
            out[key] = value
        return out
    doc = json.loads(path.read_text("utf-8"), object_pairs_hook=unique)
    if (type(doc) is not dict or set(doc) != {"schemaVersion", "entries"}
            or type(doc["schemaVersion"]) is not int or doc["schemaVersion"] != 1):
        raise ValueError("invalid first-Release manifest schema")
    entries = doc["entries"]
    if type(entries) is not list or not 3 <= len(entries) <= 128 - len(ALLOWED):
        raise ValueError("unsafe protected first-Release manifest size")
    sources, metadata = {}, {}
    for row in entries:
        if type(row) is not dict or set(row) != {
            "name", "upstreamRepository", "displayName", "description", "license"
        }:
            raise ValueError("invalid first-Release manifest entry schema")
        name, upstream = row["name"], row["upstreamRepository"]
        if (type(name) is not str or not _NEW_NAME.fullmatch(name)
                or name in ALLOWED or name in sources or type(upstream) is not str
                or not _NEW_UPSTREAM.fullmatch(upstream)):
            raise ValueError("unregistered or duplicate first-Release identity")
        for field in ("displayName", "description", "license"):
            value = row[field]
            if (type(value) is not str or not 1 <= len(value) <= 500
                    or any(ord(c) < 32 for c in value)):
                raise ValueError("unsafe first-Release display metadata")
        sources[name] = upstream
        metadata[name] = (row["displayName"], row["description"], row["license"])
    if (list(sources) != sorted(sources)
            or any(sources.get(name) != upstream
                   for name, upstream in SEALED_FIRST_RELEASE_UPSTREAM.items())):
        raise ValueError("historical first-Release sources changed or registry unsorted")
    return sources, metadata


FIRST_RELEASE_SOURCES, FIRST_RELEASE = load_first_release_registry(
    Path(__file__).resolve().parents[1] / "config/first-release-registry.json"
)
INTAKE_ALLOWED = {**ALLOWED, **FIRST_RELEASE_SOURCES}

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SEMVER = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
RUN = re.compile(r"^[1-9][0-9]*$")
SUFFIXES = (".zip", ".spdx.json", ".vulnerabilities.json")

class Denied(ValueError):
    pass

def require(test, why):
    if not test:
        raise Denied(why)

def majors(ext):
    p=ext.get("postgresql",{})
    if isinstance(p.get("majors"),list):
        nums=p["majors"]
    else:
        lo,hi=p.get("minMajor"),p.get("maxMajor")
        require(type(lo) is int and type(hi) is int and lo<=hi,
                "invalid PG major range")
        nums=list(range(lo,hi+1))
    require(bool(nums) and all(type(n) is int and n in range(14,20) for n in nums)
            and nums==sorted(set(nums)), "invalid PG major set")
    return nums

def source_map(ext):
    name=ext.get("name")
    require(isinstance(name,str) and name in INTAKE_ALLOWED
            and ext.get("upstream",{}).get("repository")==INTAKE_ALLOWED[name],
            "untrusted extension / upstream identity")
    upstream=ext["upstream"]
    allowed=majors(ext)
    series=upstream.get("perPostgresql")
    if series is not None:
        require(isinstance(series,dict) and set(series)=={str(m) for m in allowed},
                "incomplete per-major upstream set")
    src={}
    for m in allowed:
        o=series[str(m)] if series is not None else upstream
        require(isinstance(o,dict) and isinstance(o.get("ref"),str)
                and REF.fullmatch(o["ref"]) is not None
                and isinstance(o.get("version"),str)
                and SEMVER.fullmatch(o["version"]) is not None
                and isinstance(o.get("commit"),str)
                and SHA.fullmatch(o["commit"]) is not None,
                "missing pinned upstream identity for PG"+str(m))
        src[m]=o
    return src

def tag_for(ext, revision):
    require(isinstance(revision,str) and RUN.fullmatch(revision),
            "invalid create-only release revision")
    src=source_map(ext)
    latest=src[max(src)]
    if ext["name"]=="pg_bigm":
        stem=latest["ref"]
        require(re.fullmatch(r"v[0-9]+\.[0-9]+-[0-9]{8}",stem),
                "pg_bigm dated versioned tag missing")
    else:
        stem="v"+latest["version"]
    return stem+"-windows."+revision

# The sole initial metadata seed is the protected first-release manifest.
# Real public ZIP/SBOM/attestation and main-PUBLISH checks remain mandatory.


def seed_verified_first_release(ext, contract):
    """In-memory Catalog v2 seed; never creates a public record by itself."""
    name = ext.get("name")
    require(name in FIRST_RELEASE, "first-release Catalog seed not authorized")
    src = source_map(ext)  # exact immutable full upstream commit for every major
    require(contract.get("contractVersion") == 2 and contract.get("extension") == name
            and isinstance(contract.get("runtimeRequirements"), dict),
            "first-release Test Contract v2 missing")
    preload = contract["runtimeRequirements"].get("preload")
    require(preload in ("none", "optional", "shared"),
            "unknown initial preload requirement")
    display, description, license_name = FIRST_RELEASE[name]
    return {
        "schemaVersion": 2, "name": name, "displayName": display,
        "description": description,
        "upstream": {"repository": INTAKE_ALLOWED[name], "version": src[max(src)]["version"]},
        "repository": "pgextwin/" + name, "license": license_name,
        "architecture": "x64",
        "latest": {}, "postgresql": {},
        "runtime": {"sharedPreloadLibraries": [name] if preload == "shared" else [],
                    "requirements": {}},
        "capabilities": {}, "capabilitiesSource": {},
    }


def evidence_paths(pins):
    # Distinct commits of the same file represent distinct evidence.
    return Counter((repo.lower(), path) for repo, _, path in set(pins))


def verify_license_rollover(repo, tag, old_tag, source_commit, previous_licenses,
                            versions, licenses_by_major):
    licenses = {major: license_for(licenses_by_major.get(major)) for major in versions}
    for major in sorted(licenses.keys() & previous_licenses.keys()):
        old_pins = license_pins(previous_licenses[major])
        new_pins = license_pins(licenses[major])
        require(evidence_paths(old_pins) <= evidence_paths(new_pins),
                f"established license evidence missing for PG{major}")
        if tag != old_tag:
            require(all(commit == source_commit for source, commit, _ in new_pins if source.lower() == repo),
                    f"packaging license evidence must use the new source commit for PG{major}")
    return licenses


def map_inventory(existing, repo, tag, source_commit, versions, licenses_by_major, load_previous):
    inventory = existing.get("releaseInventory", {})
    current = inventory.get("current", {})
    old_tag = existing.get("latest", {}).get("releaseTag")
    require(not current or current["releaseTag"] == old_tag,
            "current license evidence belongs to a different Release")
    previous_licenses = current.get("licensesByMajor", {})
    licenses = verify_license_rollover(repo, tag, old_tag, source_commit, previous_licenses,
                                       versions, licenses_by_major)
    history = []
    for snapshot in inventory.get("history", []):
        packages = [row for row in snapshot["packages"]
                    if versions.get(row["pgMajor"]) != row["version"]]
        if packages and snapshot["releaseTag"] != tag:
            history.append({**snapshot, "packages": packages})

    if old_tag and old_tag != tag:
        packages = []
        for major, old in sorted(existing["postgresql"].items(), key=lambda item: int(item[0])):
            if old.get("available") is not True:
                continue
            version = version_for(existing["upstream"], major)
            require(isinstance(version, str) and bool(version.strip()), "previous package version missing")
            if versions.get(major) == version:
                continue
            try:
                license_info = license_for(previous_licenses.get(major))
            except ValueError as exc:
                raise Denied(f"previous Release {old_tag} lacks license evidence for PG{major}") from exc
            packages.append({
                "pgMajor": major, "version": version, "asset": old["asset"], "sha256": old["sha256"],
                "downloadUrl": old["downloadUrl"], "license": license_info,
            })
        if packages:
            require(load_previous is not None, "previous Release admission evidence required")
            commit, release = load_previous(old_tag)
            require(isinstance(commit, str) and SHA.fullmatch(commit), "previous Catalog admission missing")
            release_id, assets = release_assets(repo, old_tag, release)
            for row in packages:
                row["assetId"] = match_zip(repo, old_tag, row["pgMajor"], row, assets)
                del row["downloadUrl"]
            history.append({"releaseTag": old_tag, "releaseId": release_id,
                            "admission": {"catalogCommit": commit}, "packages": packages})
    return {"current": {"releaseTag": tag, "licensesByMajor": licenses},
            "history": sorted(history, key=lambda row: row["releaseTag"])}


def map_verified_release(existing, release, ext, contract, assets, digests,
                         source_commit, required_majors, *, licenses_by_major, load_previous=None,
                         repository_id=None, previous_ledger=None, previous_admission=None):
    """Record transformation only: caller independently proves signature/bytes."""
    require(isinstance(existing,dict) and isinstance(release,dict)
            and isinstance(ext,dict) and isinstance(contract,dict),
            "incomplete release mapping inputs")
    src=source_map(ext)
    name=ext["name"]
    repo="pgextwin/"+name
    require(existing.get("schemaVersion")==2 and existing.get("name")==name
            and existing.get("repository")==repo
            and existing.get("upstream",{}).get("repository")==INTAKE_ALLOWED[name],
            "catalog/upstream identity changed")
    require(contract.get("contractVersion")==2
            and contract.get("extension")==name
            and isinstance(contract.get("coverage"),dict)
            and isinstance(contract.get("functionalScenarios"),list)
            and isinstance(contract.get("runtimeRequirements"),dict),
            "invalid Test Contract v2 for extension")
    require(isinstance(source_commit,str) and SHA.fullmatch(source_commit),
            "unpinned packaging main SHA")
    tag=release.get("tag_name")
    require(isinstance(tag,str) and "-windows." in tag
            and tag==tag_for(ext,tag.rsplit("-windows.",1)[1]),
            "Release tag/version does not match pinned extension manifest")
    require(release.get("draft") is False and release.get("prerelease") is False
            and bool(release.get("published_at"))
            and release.get("target_commitish")==source_commit,
            "Release is unpublished or not at verified immutable source SHA")
    release_url = f"https://github.com/{repo}/releases/tag/{tag}"
    download_base = f"https://github.com/{repo}/releases/download/{tag}/"
    require(release.get("html_url") == release_url, "noncanonical public Release URL")
    require(isinstance(required_majors,list)
            and bool(required_majors)
            and required_majors==sorted(set(required_majors))
            and set(required_majors).issubset(src),
            "release PG major coverage is incomplete or duplicate")
    require(isinstance(assets,dict) and isinstance(digests,dict),
            "missing exact signed asset digest input")
    expected={"SHA256SUMS.txt"}
    for major in required_majors:
        stem=name+"-"+src[major]["ref"]+"-pg"+str(major)+"-windows-x64"
        expected.update(stem+suf for suf in SUFFIXES)
    require(set(assets)==set(digests)==expected,
            "missing/extra signed ZIP, SPDX or Grype assets")
    for fn in expected:
        a=assets[fn]
        require(isinstance(a,dict) and a.get("name")==fn
                and a.get("state")=="uploaded"
                and isinstance(digests[fn],str)
                and DIGEST.fullmatch(digests[fn])
                and a.get("digest")=="sha256:"+digests[fn],
                "GitHub-hosted asset does not match exact SHA256: "+fn)
        if fn == "SHA256SUMS.txt" or fn.endswith(".zip"):
            require(a.get("browser_download_url") == download_base + fn,
                    "noncanonical public Release asset URL: " + fn)
    versions = {str(major): src[major]["version"] for major in required_majors}
    out=copy.deepcopy(existing)
    if "perPostgresql" in ext["upstream"]:
        out["upstream"].pop("version", None)
        out["upstream"]["perPostgresql"]={
            str(m):{"version":src[m]["version"],"ref":src[m]["ref"]}
            for m in sorted(src)}
    else:
        out["upstream"].pop("perPostgresql", None)
        out["upstream"]["version"]=src[max(src)]["version"]
    out["latest"]={
        "releaseTag":tag,"publishedAt":release["published_at"],
        "releaseUrl":release_url,
        "checksumsAsset":"SHA256SUMS.txt"
    }
    for m in required_majors:
        stem=name+"-"+src[m]["ref"]+"-pg"+str(m)+"-windows-x64"
        def entry(suffix):
            fn=stem+suffix
            return {"available":True,"asset":fn,
                    "downloadUrl":download_base+fn,
                    "sha256":digests[fn]}
        item=entry(".zip")
        item["evidence"]={
            "buildProvenanceAttestation":{"available":True},
            "sbom":entry(".spdx.json"),
            "sbomAttestation":{"available":True},
            "vulnerabilityReport":entry(".vulnerabilities.json")
        }
        out["postgresql"][str(m)]=item
    # Majors absent from this Release retain their Website availability marker.
    for major in out["postgresql"].keys() - versions.keys():
        out["postgresql"][major] = {"available": False}
    out["runtime"]["requirements"]=copy.deepcopy(contract["runtimeRequirements"])
    out["capabilities"]={
        "testContractVersion":2,
        "coverage":copy.deepcopy(contract["coverage"]),
        "functionalScenarios":copy.deepcopy(contract["functionalScenarios"])
    }
    out["capabilitiesSource"]={
        "repository":repo,
        "path":"config/test-contract.json",
        "commit":source_commit
    }
    if repository_id is None:
        # v2 replay for callers verifying records from before the ledger.
        out["releaseInventory"] = map_inventory(existing, repo, tag, source_commit, versions,
                                                licenses_by_major, load_previous)
        return out

    previous = package_ledger.current_release(previous_ledger) if previous_ledger else None
    previous_licenses = {row["pgMajor"]: row["license"] for row in previous["packages"]} if previous else {}
    licenses = verify_license_rollover(repo, tag, previous["releaseTag"] if previous else None,
                                       source_commit, previous_licenses, versions, licenses_by_major)
    latest = package_ledger.pin_release(out, release, licenses)
    history = []
    if previous_ledger:
        require(previous_ledger["repositoryId"] == repository_id,
                "previously admitted repository ID changed")
        history = package_ledger.superseded_releases(previous_ledger, latest, previous_admission)
    return package_ledger.ledger_record(out, repository_id, latest, history)
