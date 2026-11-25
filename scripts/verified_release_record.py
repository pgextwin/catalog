#!/usr/bin/env python3
"""Pure, fail-closed Catalog v2 mapping for independently verified signed public Releases.

Does not download artifacts, verify GitHub attestations, dispatch workflows,
merge PRs or publish Releases. Call ONLY after a separate fully signed Release
verifier has checked actual remote asset bytes and provenance.
"""
from __future__ import annotations
from collections import Counter
import copy
import hashlib
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


def _unique_json_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Denied("duplicate JSON key: " + key)
        out[key] = value
    return out


def _valid_text(value, *, max_len=500):
    return (
        type(value) is str
        and 1 <= len(value) <= max_len
        and not any(ord(c) < 32 for c in value)
    )


def git_blob_sha_bytes(raw: bytes) -> str:
    """Compute the exact Git sha1 blob object ID for raw file bytes."""
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def identity_blob_sha(path) -> str | None:
    """Return the Git blob SHA for identities/<name>.json, or None if absent."""
    target = Path(path)
    require(not target.is_symlink(), "symlinked Catalog identity path denied")
    if not target.exists():
        return None
    require(target.is_file(), "non-file Catalog identity path denied")
    return git_blob_sha_bytes(target.read_bytes())


def read_identity(path, *, expected_name=None):
    """Read and validate one Catalog identities/<name>.json record."""
    target = Path(path)
    require(
        target.is_file() and not target.is_symlink() and 0 < target.stat().st_size <= 65536,
        "missing or oversized Catalog identity record",
    )
    doc = json.loads(target.read_text("utf-8"), object_pairs_hook=_unique_json_object)
    allowed_top = {
        "schemaVersion", "name", "displayName", "upstreamRepository",
        "description", "intake", "distribution", "research",
    }
    required_top = {"schemaVersion", "name", "upstreamRepository", "description", "intake", "research"}
    require(
        type(doc) is dict and required_top.issubset(doc) and set(doc).issubset(allowed_top)
        and type(doc["schemaVersion"]) is int and doc["schemaVersion"] == 1,
        "invalid Catalog identity schema",
    )
    name = doc["name"]
    require(
        type(name) is str and _NEW_NAME.fullmatch(name) is not None
        and target.name == name + ".json"
        and (expected_name is None or name == expected_name),
        "Catalog identity name or filename mismatch",
    )
    require(
        type(doc["upstreamRepository"]) is str and _NEW_UPSTREAM.fullmatch(doc["upstreamRepository"]) is not None
        and _valid_text(doc["description"]),
        "unsafe Catalog identity metadata",
    )
    if "displayName" in doc:
        require(
            _valid_text(doc["displayName"]) and doc["displayName"] != name,
            "unsafe Catalog identity displayName",
        )
    require(type(doc["research"]) is dict, "invalid Catalog identity research metadata")
    intake = doc["intake"]
    allowed_intake = {
        "class", "distributionAllowed", "registrationSource",
        "expectedUpstreamRepository", "sealedUpstream",
    }
    require(
        type(intake) is dict and {"class", "distributionAllowed"}.issubset(intake)
        and set(intake).issubset(allowed_intake),
        "invalid Catalog identity intake schema",
    )
    intake_class = intake["class"]
    if intake_class == "research-only":
        require(
            intake["distributionAllowed"] is False
            and "distribution" not in doc
            and not ({"registrationSource", "expectedUpstreamRepository", "sealedUpstream"} & set(intake)),
            "invalid research-only Catalog identity",
        )
    elif intake_class == "distributed":
        require(
            intake["distributionAllowed"] is True
            and intake.get("registrationSource") in ("historical-core", "first-release-registry")
            and type(intake.get("sealedUpstream")) is bool
            and intake.get("expectedUpstreamRepository") == doc["upstreamRepository"],
            "invalid distributed Catalog identity intake",
        )
        dist = doc.get("distribution")
        require(
            type(dist) is dict
            and {"repository", "license", "ledgerPath"}.issubset(dist)
            and set(dist).issubset({"repository", "license", "ledgerPath", "externalSourceRegistry"})
            and dist["repository"] == "pgextwin/" + name
            and dist["ledgerPath"] == f"{package_ledger.DIRECTORY}/{name}.json"
            and _valid_text(dist["license"]),
            "invalid Catalog identity distribution metadata",
        )
        if "externalSourceRegistry" in dist:
            require(
                dist["externalSourceRegistry"] == "external/windows-candidates-v1.json",
                "invalid Catalog identity externalSourceRegistry",
            )
    else:
        raise Denied("unknown Catalog identity intake class")
    return doc


def read_index_v3(path):
    """Read and strictly validate root index.json (schema v3)."""
    target = Path(path)
    require(
        target.is_file() and not target.is_symlink() and 0 < target.stat().st_size <= 262144,
        "missing or oversized Catalog v3 index",
    )
    index = json.loads(target.read_text("utf-8"), object_pairs_hook=_unique_json_object)
    require(
        type(index) is dict
        and set(index) == {"schemaVersion", "identitiesDir", "packagesDir", "extensions", "identities"}
        and type(index["schemaVersion"]) is int and index["schemaVersion"] == 3
        and index["identitiesDir"] == "identities"
        and index["packagesDir"] == package_ledger.DIRECTORY,
        "invalid Catalog v3 index schema",
    )
    extensions = index["extensions"]
    require(
        type(extensions) is list and bool(extensions)
        and all(type(n) is str and _NEW_NAME.fullmatch(n) is not None for n in extensions)
        and extensions == sorted(set(extensions)),
        "invalid or duplicate Catalog distribution roster",
    )
    identities = index["identities"]
    require(type(identities) is list and bool(identities), "invalid Catalog v3 identities list")
    seen = set()
    distributed_entries = {}
    for entry in identities:
        require(
            type(entry) is dict and {"name", "path", "intakeClass"}.issubset(entry)
            and set(entry).issubset({"name", "path", "intakeClass", "ledgerPath"}),
            "invalid Catalog v3 identity entry",
        )
        name = entry["name"]
        require(
            type(name) is str and _NEW_NAME.fullmatch(name) is not None and name not in seen
            and entry["path"] == f"identities/{name}.json"
            and entry["intakeClass"] in ("distributed", "research-only"),
            "invalid or duplicate Catalog v3 identity entry",
        )
        seen.add(name)
        if entry["intakeClass"] == "distributed":
            require(
                entry.get("ledgerPath") == f"{package_ledger.DIRECTORY}/{name}.json",
                "missing/invalid ledgerPath in Catalog v3 index",
            )
            distributed_entries[name] = entry
        else:
            require("ledgerPath" not in entry, "research-only entry must not carry ledgerPath")
    require(
        [entry["name"] for entry in identities] == sorted(seen)
        and set(distributed_entries) == set(extensions),
        "Catalog v3 index roster and identities disagree",
    )
    return index


def load_identities_intake(identities_dir):
    """Derive distributed intake allowlists and sealed upstream expectations from identities/."""
    directory = Path(identities_dir)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("missing or invalid Catalog identities directory")
    historical_sources, first_sources, first_meta, identities = {}, {}, {}, {}
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".json":
            raise ValueError("unexpected entry in Catalog identities directory: " + entry.name)
        stem = entry.stem
        if not _NEW_NAME.fullmatch(stem):
            raise ValueError("invalid identity filename: " + entry.name)
        doc = read_identity(entry, expected_name=stem)
        intake = doc["intake"]
        if intake["class"] == "research-only":
            continue
        reg = intake["registrationSource"]
        upstream = intake["expectedUpstreamRepository"]
        sealed = intake["sealedUpstream"]
        if reg == "historical-core":
            if sealed is not True or ALLOWED.get(stem) != upstream:
                raise ValueError("historical-core identity mismatch: " + stem)
            historical_sources[stem] = upstream
        else:
            if stem in ALLOWED:
                raise ValueError("duplicate historical-core/first-release identity: " + stem)
            if stem in SEALED_FIRST_RELEASE_UPSTREAM:
                if sealed is not True or upstream != SEALED_FIRST_RELEASE_UPSTREAM[stem]:
                    raise ValueError("historical sealed first-release identity changed: " + stem)
            first_sources[stem] = upstream
            first_meta[stem] = (
                doc.get("displayName", stem),
                doc["description"],
                doc["distribution"]["license"],
            )
        identities[stem] = doc
    if historical_sources != ALLOWED:
        raise ValueError("incomplete historical-core Catalog identities")
    if any(first_sources.get(name) != upstream
           for name, upstream in SEALED_FIRST_RELEASE_UPSTREAM.items()):
        raise ValueError("historical sealed first-Release sources missing or changed")
    if not 3 <= len(first_sources) <= 128 - len(ALLOWED):
        raise ValueError("unsafe protected first-Release identities count")
    return historical_sources, first_sources, first_meta, identities


IDENTITIES_DIR = Path(__file__).resolve().parents[1] / "identities"
_HISTORICAL_SOURCES, FIRST_RELEASE_SOURCES, FIRST_RELEASE, DISTRIBUTED_IDENTITIES = (
    load_identities_intake(IDENTITIES_DIR)
)
INTAKE_ALLOWED = {**_HISTORICAL_SOURCES, **FIRST_RELEASE_SOURCES}


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

# The sole initial metadata seed is the protected distributed identity.
# Real public ZIP/SBOM/attestation and main-PUBLISH checks remain mandatory.


def _validate_distributed_identity_doc(identity, name):
    require(type(identity) is dict and type(identity.get("schemaVersion")) is int
            and identity["schemaVersion"] == 1 and identity.get("name") == name,
            "invalid Catalog identity record")
    require(isinstance(name, str) and name in INTAKE_ALLOWED,
            "untrusted extension / upstream identity")
    intake = identity.get("intake")
    require(type(intake) is dict and intake.get("class") == "distributed"
            and intake.get("distributionAllowed") is True
            and intake.get("expectedUpstreamRepository") == identity.get("upstreamRepository") == INTAKE_ALLOWED[name],
            "untrusted extension / upstream identity")
    dist = identity.get("distribution")
    require(type(dist) is dict and dist.get("repository") == "pgextwin/" + name
            and dist.get("ledgerPath") == f"{package_ledger.DIRECTORY}/{name}.json"
            and _valid_text(dist.get("license"))
            and _valid_text(identity.get("description")),
            "invalid Catalog identity distribution metadata")
    if "displayName" in identity:
        require(_valid_text(identity["displayName"]) and identity["displayName"] != name,
                "invalid Catalog identity displayName")
    if "externalSourceRegistry" in dist:
        require(dist["externalSourceRegistry"] == "external/windows-candidates-v1.json",
                "invalid Catalog identity externalSourceRegistry")
    return identity


def candidate_from_identity_and_ledger(identity, ledger):
    """Build the current Catalog record candidate from identity + ledger (no v2/landscape reads)."""
    require(type(identity) is dict and type(ledger) is dict,
            "missing Catalog identity or package ledger")
    name = identity.get("name")
    _validate_distributed_identity_doc(identity, name)
    require(type(ledger.get("schemaVersion")) is int and ledger["schemaVersion"] == 1
            and ledger.get("name") == name
            and ledger.get("repository") == "pgextwin/" + name,
            "Catalog identity/ledger mismatch")
    try:
        projected = package_ledger.website_record(ledger)
    except (ValueError, KeyError, TypeError) as exc:
        raise Denied(str(exc)) from exc
    dist = identity["distribution"]
    expected_display = identity.get("displayName", name)
    require(projected.get("name") == name
            and projected.get("displayName") == expected_display
            and projected.get("description") == identity["description"]
            and (projected.get("upstream") or {}).get("repository") == identity["upstreamRepository"]
            and projected.get("repository") == dist["repository"]
            and projected.get("license") == dist["license"]
            and ("externalSourceRegistry" in projected) == ("externalSourceRegistry" in dist)
            and projected.get("externalSourceRegistry") == dist.get("externalSourceRegistry"),
            "Catalog identity and package ledger disagree")
    return projected


def seed_verified_first_release(ext, contract, *, identity=None):
    """In-memory Catalog v2 seed from protected identity; never creates a public record by itself."""
    name = ext.get("name")
    require(name in FIRST_RELEASE_SOURCES, "first-release Catalog seed not authorized")
    src = source_map(ext)  # exact immutable full upstream commit for every major
    require(contract.get("contractVersion") == 2 and contract.get("extension") == name
            and isinstance(contract.get("runtimeRequirements"), dict),
            "first-release Test Contract v2 missing")
    preload = contract["runtimeRequirements"].get("preload")
    require(preload in ("none", "optional", "shared"),
            "unknown initial preload requirement")
    if identity is not None:
        _validate_distributed_identity_doc(identity, name)
        require(identity["intake"].get("registrationSource") == "first-release-registry"
                and identity["upstreamRepository"] == FIRST_RELEASE_SOURCES[name],
                "first-release Catalog identity mismatch")
        display = identity.get("displayName", name)
        description = identity["description"]
        license_name = identity["distribution"]["license"]
        ext_registry = identity["distribution"].get("externalSourceRegistry")
    else:
        require(name in FIRST_RELEASE, "first-release Catalog seed not authorized")
        display, description, license_name = FIRST_RELEASE[name]
        ext_registry = (DISTRIBUTED_IDENTITIES.get(name) or {}).get("distribution", {}).get("externalSourceRegistry")
    seed = {
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
    if ext_registry is not None:
        seed["externalSourceRegistry"] = ext_registry
    return seed


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
                         repository_id=None, previous_ledger=None, previous_admission=None,
                         identity=None):
    """Record transformation only: caller independently proves signature/bytes."""
    require(isinstance(release, dict) and isinstance(ext, dict) and isinstance(contract, dict),
            "incomplete release mapping inputs")
    src=source_map(ext)
    name=ext["name"]
    repo="pgextwin/"+name
    if identity is not None:
        _validate_distributed_identity_doc(identity, name)
        if existing is None:
            if previous_ledger is not None:
                existing = candidate_from_identity_and_ledger(identity, previous_ledger)
            else:
                existing = seed_verified_first_release(ext, contract, identity=identity)
        else:
            require(
                existing.get("displayName") == identity.get("displayName", name)
                and existing.get("description") == identity["description"]
                and existing.get("license") == identity["distribution"]["license"],
                "catalog/identity metadata mismatch",
            )
    require(isinstance(existing, dict), "incomplete release mapping inputs")
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


def project_first_intake_files(name, ledger, *, expected_identity_blob_sha, root=Path(".")):
    """Compute first-intake identities/<name>.json and root index.json updates.

    Enforces that the protected identity blob on main matches expected_identity_blob_sha
    from verification time (fail closed). Never reads legacy extensions/ or landscape/**.
    """
    root = Path(root)
    require(isinstance(name, str) and name in FIRST_RELEASE_SOURCES,
            "unknown first-intake identity")
    require(
        type(ledger) is dict
        and type(ledger.get("schemaVersion")) is int and ledger["schemaVersion"] == 1
        and ledger.get("name") == name
        and ledger.get("repository") == "pgextwin/" + name
        and (ledger.get("upstream") or {}).get("repository") == FIRST_RELEASE_SOURCES[name],
        "unknown first-intake ledger identity",
    )
    require(
        expected_identity_blob_sha is None
        or (isinstance(expected_identity_blob_sha, str)
            and SHA.fullmatch(expected_identity_blob_sha) is not None),
        "invalid expected identityBlobSha",
    )
    id_path = root / "identities" / (name + ".json")
    actual_blob_sha = identity_blob_sha(id_path)
    require(actual_blob_sha == expected_identity_blob_sha,
            "protected Catalog identity blob changed after verification")
    require(actual_blob_sha is not None, "protected Catalog identity missing for first intake")
    identity = read_identity(id_path, expected_name=name)
    require(
        identity["intake"]["class"] == "distributed"
        and identity["intake"]["distributionAllowed"] is True
        and identity["intake"].get("registrationSource") == "first-release-registry"
        and identity["upstreamRepository"] == FIRST_RELEASE_SOURCES[name],
        "first-intake identity is not an authorized first-release record",
    )
    require(
        identity.get("displayName", name) == ledger.get("displayName")
        and identity["description"] == ledger.get("description")
        and identity["distribution"]["license"] == ledger.get("license"),
        "first-intake ledger differs from protected identity metadata",
    )
    try:
        current = package_ledger.current_release(ledger)
    except (ValueError, KeyError, TypeError) as exc:
        raise Denied(str(exc)) from exc
    tag = current.get("releaseTag")
    published_at = current.get("publishedAt")
    release_url = f"https://github.com/pgextwin/{name}/releases/tag/{tag}"
    require(
        isinstance(tag, str) and bool(tag)
        and isinstance(published_at, str) and len(published_at) >= 10,
        "missing independently verified public first-Release identity",
    )
    index = read_index_v3(root / "index.json")
    require(name not in index["extensions"],
            "first-intake index is not a protected unregistered source")

    updated_identity = copy.deepcopy(identity)
    research = updated_identity.setdefault("research", {})
    for key in ("status", "candidateRationale", "roadmap", "notPlannedReason",
                "notPlannedReasonJa", "reasonCode"):
        research.pop(key, None)
    if not research.get("lastReviewed"):
        research["lastReviewed"] = published_at[:10]
    upstream_url = "https://github.com/" + FIRST_RELEASE_SOURCES[name]
    existing_urls = research.get("evidenceUrls")
    if isinstance(existing_urls, list):
        urls = list(dict.fromkeys(existing_urls))
    else:
        urls = []
    if release_url not in urls:
        urls = [release_url, *urls]
    if upstream_url not in urls:
        urls.append(upstream_url)
    research["evidenceUrls"] = urls
    if not isinstance(research.get("windowsBinarySources"), list):
        research["windowsBinarySources"] = []

    updated_index = copy.deepcopy(index)
    updated_index["extensions"] = sorted(set(index["extensions"]) | {name})
    entries_by_name = {entry["name"]: entry for entry in updated_index["identities"]}
    entries_by_name[name] = {
        "name": name,
        "path": f"identities/{name}.json",
        "intakeClass": "distributed",
        "ledgerPath": f"{package_ledger.DIRECTORY}/{name}.json",
    }
    updated_index["identities"] = [entries_by_name[n] for n in sorted(entries_by_name)]
    return {
        f"identities/{name}.json": updated_identity,
        "index.json": updated_index,
    }
