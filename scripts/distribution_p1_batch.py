#!/usr/bin/env python3
"""Issue #112: read-only, fail-closed per-Release/per-PG genuine P1 batch.

Never treats an Actions artifact, a fixture or a cached receipt as Release or
cryptographic proof. A PASS_CANDIDATE requires fresh per-row gh Sigstore checks;
formal acceptance remains a separate versioned Issue/ledger decision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from zipfile import ZipFile, BadZipFile

from distribution_manifest_v1 import Denied, require, strict_json, verify_archive_members
from distribution_release_audit_p1 import (
    api_json, pinned_content, policy_load, resolve_tag, gh_read,
)
from distribution_release_verify_p1 import (
    PROVENANCE, SPDX, sha, verified_catalog, release_assets, require_asset_id_pins,
    rehash_release, immutable_source, inspect_package, signed_run, parse_sums,
    verify_sigstore_offline, MAX_RELEASE,
)
from distribution_historical_p1_pg14 import (
    PIN as HISTORICAL_PG14_PIN, parse_original_historical_sums,
)

SCHEMA = "pgextwin-p1-genuine-fleet-batch/v1"
VERIFIER = "batch-v3-full-zip-structure-and-observed-run;distribution_release_verify_p1.py"
BASELINE = ("pg_bigm", "14", 1405047175, 408449466, 626562095)
NAMES = ("hypopg", "orafce", "pg_bigm", "pg_cron", "pg_hint_plan", "pg_ivm",
         "pg_partman", "pg_qualstats", "pg_repack", "pg_stat_monitor",
         "pgaudit", "plpgsql_check", "set_user", "wal2json")
MAJORS = ("14", "15", "16", "17", "18")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def original_profile(name, release):
    if name == "pg_bigm" and release.get("id") == HISTORICAL_PG14_PIN["releaseId"]:
        require(release.get("tag_name") == HISTORICAL_PG14_PIN["tag"]
                and release.get("target_commitish") == HISTORICAL_PG14_PIN["packaging"],
                "historical Release source identity changed")
        return "historical-pg_bigm-original-checksums/v1"
    return "main-promotion/v1"


def parse_pinned_original_sums(data, expected_names):
    """Exact original spelling observed from real, full-SHA-pinned Release bytes.

    Parse only homogeneous 15-row canonical basenames or homogeneous literal
    ./basenames; no ambiguous aliases, traversal, mixed forms or duplicates.
    This is solely Release transport syntax, NOT a workflow/signature profile.
    """
    require(type(data) is bytes and 0 < len(data) <= 8192
            and type(expected_names) is set and len(expected_names) == 15,
            "invalid original checksum shape")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise Denied("original checksum non-ASCII") from exc
    require(len(lines) == 15, "missing/extra original checksum lines")
    canonical = [re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
                 for line in lines]
    dot = [re.fullmatch(r"([a-f0-9]{64})  \./([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
           for line in lines]
    if all(canonical):
        sums = parse_sums(data)
    else:
        require(all(dot), "mixed/unsafe original checksum aliases")
        require(len({m[2].casefold() for m in dot}) == 15,
                "duplicate/case-colliding dot-prefixed aliases")
        sums = parse_sums(("\n".join(m[1] + "  " + m[2] for m in dot) +
                           "\n").encode("ascii"))
    require(set(sums) == expected_names and
            len({n.casefold() for n in sums}) == len(sums),
            "original checksum names differ from complete pinned Release")
    return sums


def rehash_dot_pinned_original(directory, assets, record, *, historical=False):
    """Recheck all original bytes against numeric-pinned metadata and Catalog."""
    require(directory.is_dir() and not directory.is_symlink()
            and len(assets) == 16 and sum(a["size"] for a in assets.values()) <= MAX_RELEASE,
            "pinned Release 16-Asset shape mismatch")
    entries = list(directory.iterdir())
    require(len(entries) == len(assets) and {p.name for p in entries} == set(assets)
            and all(p.is_file() and not p.is_symlink() for p in entries),
            "Release missing/extra/linked payload")
    hashes = {}
    for filename, asset in assets.items():
        path = directory / filename
        require(path.stat().st_size == asset["size"], "original Asset size mismatch")
        hashes[filename] = sha(path)
        require(asset["digest"] == "sha256:" + hashes[filename],
                "original Asset real-byte SHA mismatch")
    raw = (directory / "SHA256SUMS.txt").read_bytes()
    sums = (parse_original_historical_sums(raw, set(assets) - {"SHA256SUMS.txt"})
            if historical else parse_pinned_original_sums(
                raw, set(assets) - {"SHA256SUMS.txt"}))
    require(all(hashes[n] == digest for n, digest in sums.items()),
            "15 original checksums disagree with actual Asset bytes")
    for major, row in record["postgresql"].items():
        if row.get("available") is not True:
            continue
        require(hashes[row["asset"]] == row["sha256"],
                "Catalog ZIP real-byte SHA mismatch " + major)
        for field in ("sbom", "vulnerabilityReport"):
            evidence = row["evidence"][field]
            require(hashes[evidence["asset"]] == evidence["sha256"],
                    "Catalog SBOM/Grype real-byte SHA mismatch " + major)
    return hashes


def rehash_common_original(directory, assets, record, name, release):
    """Strict ordinary P1 first; original syntax fallback only for pinned IDs.

    The original immutable SHA256SUMS and all 15 other assets are SHA256-matched
    before alias parsing. This does not change promotion/source/run/crypto policy.
    """
    if original_profile(name, release) != "main-promotion/v1":
        require(assets["SHA256SUMS.txt"]["id"] == HISTORICAL_PG14_PIN["sumsAssetId"]
                and assets["SHA256SUMS.txt"]["digest"] ==
                    "sha256:" + HISTORICAL_PG14_PIN["sumsSha256"],
                "historical checksum numeric ID/SHA pin differs")
        return rehash_dot_pinned_original(directory, assets, record, historical=True)
    try:
        return rehash_release(directory, assets, record)
    except Denied as exc:
        require(str(exc) == "invalid/duplicate checksum",
                "original P1 real-byte verification rejected: " + str(exc))
    # Reached only for already authenticated 14-Release/224-Asset numeric ID
    # candidate Policy, unchanged SHA of the ORIGINAL checksum Asset and bytes.
    return rehash_dot_pinned_original(directory, assets, record)


def inspect_release_structure(directory, record, name, release):
    """Genuine original ZIP CRC/SPDX/Grype validation before profile decisions.

    Observed package/Run metadata is diagnostic, UNTRUSTED until the per-PG
    exact source/Run and two real Sigstore checks succeed. No generalization
    of the sole formally accepted historical PG14 cryptographic profile.
    """
    details = {}
    for major, row in record["postgresql"].items():
        if row.get("available") is not True:
            continue
        try:
            path = directory / row["asset"]
            with ZipFile(path) as zf:
                verify_archive_members(zf)
                matches = [m for m in zf.infolist() if m.filename == "PACKAGE-INFO.json"]
                require(len(matches) == 1 and matches[0].file_size <= 262144,
                        "missing/ambiguous/oversized package metadata")
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    with zf.open(member) as stream:
                        while stream.read(1024 * 1024):
                            pass  # Exercise each member CRC with bounded reads.
                pkg = strict_json(zf.read("PACKAGE-INFO.json").decode("utf-8-sig"))
            sbom_file = directory / row["evidence"]["sbom"]["asset"]
            grype_file = directory / row["evidence"]["vulnerabilityReport"]["asset"]
            require(sbom_file.stat().st_size <= 8 * 1024 * 1024
                    and grype_file.stat().st_size <= 8 * 1024 * 1024,
                    "oversized signed SPDX/Grype inspection input")
            spdx = strict_json(sbom_file.read_bytes())
            grype = strict_json(grype_file.read_bytes())
        except (BadZipFile, OSError, RuntimeError, UnicodeError, KeyError, ValueError) as exc:
            raise Denied("original PG" + major + " ZIP/CRC/SPDX/Grype invalid") from exc
        require(type(pkg) is dict and pkg.get("schemaVersion") == 1
                and (pkg.get("package") or {}).get("name") == name
                and (pkg.get("package") or {}).get("platform") == "windows"
                and (pkg.get("package") or {}).get("architecture") == "x64"
                and (pkg.get("postgresql") or {}).get("major") == int(major),
                "original PG" + major + " PACKAGE-INFO identity invalid")
        require(spdx.get("spdxVersion") == "SPDX-2.3"
                and type(grype.get("matches")) is list,
                "original PG" + major + " SPDX/Grype structure invalid")
        workflow = pkg.get("workflowRun") or {}
        upstream = pkg.get("upstream") or {}
        package_source = pkg.get("source") or {}
        infrastructure = pkg.get("buildInfrastructure") or {}
        require(all(type(o) is dict for o in
                    (workflow, upstream, package_source, infrastructure)),
                "non-object original diagnostic structure")
        run_id = workflow.get("id")
        observed = {
            "packageEvent": workflow.get("event"),
            "packageRef": workflow.get("ref"),
            "packageRunId": run_id,
            "packageRunAttempt": workflow.get("attempt"),
            "packagePackagingSha": package_source.get("packagingCommit"),
            "packageUpstreamRef": upstream.get("ref"),
            "packageUpstreamSha": upstream.get("commit"),
            "packageSignerSha": infrastructure.get("commit"),
            "profileStatus": "UNVERIFIED_OBSERVATION_ONLY",
        }
        if type(run_id) is int and run_id > 0:
            try:
                run = api_json(name + "/actions/runs/" + str(run_id))
                observed["githubRun"] = {
                    "id": run.get("id"), "runAttempt": run.get("run_attempt"),
                    "workflow": run.get("path"), "event": run.get("event"),
                    "headBranch": run.get("head_branch"), "headSha": run.get("head_sha"),
                    "conclusion": run.get("conclusion"), "status": run.get("status"),
                    "repositoryId": (run.get("repository") or {}).get("id"),
                }
            except (Denied, OSError, TypeError, ValueError, KeyError) as exc:
                observed["githubRunLookupBlocked"] = str(exc)[:160]
        details[major] = observed
    return details


def identity(policy, name, release):
    assets = release.get("assets") or []
    return hashlib.sha256(json_bytes({
        "catalog": policy["catalogCommitSha"], "repositoryId": policy["repoIds"][name],
        "releaseId": policy["releaseIds"][name],
        "source": release["target_commitish"],
        "assets": sorted((a.get("id"), a.get("name"), a.get("size"), a.get("digest"))
                         for a in assets),
        "verifier": VERIFIER, "profile": original_profile(name, release),
        "trustedRoot": policy["rootSha256"],
    })).hexdigest()


def require_gh(policy):
    """Only the externally pinned official executable may run GET or cryptography."""
    exe = shutil.which("gh")
    require(exe is not None, "official gh unavailable")
    binary = Path(exe).resolve()
    require(binary.is_file() and not binary.is_symlink(), "unsafe gh executable")
    measured = sha(binary)
    allowed = policy.get("officialGhSha256")
    require(type(allowed) is list and allowed
            and all(type(x) is str and HEX64.fullmatch(x) for x in allowed)
            and measured in allowed, "official gh provenance/SHA256 not pinned")
    return {"binarySha256": measured, "binaryPath": str(binary)}


def fresh_root(policy, destination):
    """Refresh and verify TUF chain via official gh, never accept a root from assets."""
    for args in (("attestation", "trusted-root", "--verify-only"),
                 ("attestation", "trusted-root")):
        try:
            proc = subprocess.run(("gh",) + args, capture_output=True, timeout=120,
                                  env={**os.environ, "GH_NO_UPDATE_NOTIFIER": "1",
                                       "GH_PROMPT_DISABLED": "1"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Denied("official gh TUF update unavailable") from exc
        require(proc.returncode == 0, "TUF root/update chain did not verify")
        if len(args) == 3:
            continue
        require(0 < len(proc.stdout) <= 8 * 1024 * 1024,
                "missing/oversized TUF trusted root")
        destination.write_bytes(proc.stdout)
    require(sha(destination) == policy["rootSha256"], "TUF root differs from pinned root")
    return destination


def fetch_jobs(name, run_id, major):
    """Read exact original run jobs; no skipped/failed or omitted pages accepted."""
    path = "repos/pgextwin/" + name + "/actions/runs/" + str(run_id) + "/jobs?per_page=100"
    require(re.fullmatch(
        r"repos/pgextwin/[a-z][a-z0-9_]*/actions/runs/[1-9][0-9]*/jobs\?per_page=100",
        path), "unsafe jobs GET")
    try:
        p = subprocess.run(("gh", "api", path), capture_output=True, timeout=90,
                           env={**os.environ, "GH_NO_UPDATE_NOTIFIER": "1",
                                "GH_PROMPT_DISABLED": "1"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Denied("original jobs GET unavailable") from exc
    require(p.returncode == 0 and len(p.stdout) < 8 * 1024 * 1024,
            "original run/jobs GET failed")
    data = strict_json(p.stdout)
    jobs = data.get("jobs")
    require(type(jobs) is list and len(jobs) == data.get("total_count")
            and len(jobs) <= 100, "incomplete/duplicated job pagination")
    needle = "PostgreSQL " + major + " / Windows x64"
    matches = [j for j in jobs if needle in j.get("name", "")]
    require(len(matches) == 1 and matches[0].get("conclusion") == "success",
            "original PG-specific build job missing/failed")
    publishes = [j for j in jobs if
                 j.get("name") == "Verify signatures and SHA; create-only formal publication"]
    require(len(publishes) == 1 and publishes[0].get("conclusion") == "success",
            "original formal promotion publication job not successful")
    return {"buildJobId": matches[0]["id"], "publicationJobId": publishes[0]["id"]}


def save_object(cache, path, asset, digest):
    """Content address is not itself a verification verdict."""
    store = cache / "sha256"
    require(cache.is_dir() and not cache.is_symlink(), "unsafe evidence directory")
    store.mkdir(exist_ok=True)
    require(not store.is_symlink(), "unsafe object store")
    dest = store / digest
    require(path.stat().st_size == asset["size"] and sha(path) == digest,
            "original Release payload differs from metadata")
    if dest.exists() or dest.is_symlink():
        require(dest.is_file() and not dest.is_symlink()
                and dest.stat().st_size == asset["size"] and sha(dest) == digest,
                "stale or substituted content-addressed original")
        return
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out, path.open("rb") as src:
        shutil.copyfileobj(src, out)
    require(sha(dest) == digest, "object cache write failure")


def obtain_assets(cache, directory, assets, repo, release_tag):
    """Saved originals first; missing files fetched ONLY from pinned public Release."""
    need = []
    for name, asset in assets.items():
        digest = asset["digest"][7:]
        source = cache / "sha256" / digest
        dest = directory / name
        if source.exists() or source.is_symlink():
            require(source.is_file() and not source.is_symlink()
                    and source.stat().st_size == asset["size"]
                    and sha(source) == digest, "cached original corrupted")
            shutil.copyfile(source, dest)
        else:
            need.append(name)
    for name in need:
        # Exact pinned asset name; no wildcard expansion and no shell.
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name), "unsafe asset pattern")
        try:
            p = subprocess.run(
                ("gh", "release", "download", release_tag, "--repo", repo,
                 "--pattern", name, "--dir", str(directory), "--clobber"),
                capture_output=True, timeout=300,
                env={**os.environ, "GH_NO_UPDATE_NOTIFIER": "1",
                     "GH_PROMPT_DISABLED": "1"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Denied("original Release GET failed") from exc
        require(p.returncode == 0, "GET-only original Release asset unavailable: " + name)
        dest = directory / name
        require(dest.is_file() and not dest.is_symlink(), "missing downloaded original")
        save_object(cache, dest, assets[name], assets[name]["digest"][7:])


def get_catalog(policy):
    commit = policy["catalogCommitSha"]
    index = pinned_content("catalog", "index.json", commit)
    names = strict_json(index).get("extensions")
    require(names == list(NAMES), "fleet list differs from pinned 14 extensions")
    records = {name: pinned_content("catalog", "extensions/" + name + ".json", commit)
               for name in names}
    return verified_catalog(index, records, policy["catalogDigests"], commit)


def row_receipt(name, major, policy, release, key, measured, result, *, origin="genuine"):
    row = release["assets"]
    zip_name = next((a["name"] for a in row
                     if a["name"].endswith("-pg" + major + "-windows-x64.zip")), None)
    match = [a for a in row if a["name"] == zip_name]
    return {
        "schema": SCHEMA, "type": "row", "extension": name, "pgMajor": int(major),
        "repositoryId": policy["repoIds"][name], "releaseId": policy["releaseIds"][name],
        "assetId": match[0]["id"] if len(match) == 1 else None,
        "catalogCommit": policy["catalogCommitSha"], "releaseIdentitySha256": key,
        "packagingSha": release["target_commitish"], "verifier": VERIFIER,
        "officialGhSha256": measured.get("binarySha256"),
        "trustedRootSha256": policy["rootSha256"],
        "verificationOrigin": origin, "decision": result["decision"],
        "integrityVerified": result.get("integrityVerified") is True,
        "signatureVerified": result.get("signatureVerified") is True,
        "reason": result.get("reason", ""),
        "runId": result.get("runId"), "runAttempt": result.get("runAttempt"),
        "signatureProof": result.get("signatureProof"),
        "observedUnsignedPackage": result.get("observedUnsignedPackage"),
        "publicationAuthorized": False, "distributionAuthorized": False,
        "formalAcceptedByThisRun": False,
        "workIndividualAuditRequired": result["decision"] != "PASS_CANDIDATE",
    }


def handle_release(name, rec, policy, cache, root, measured):
    repo = "pgextwin/" + name
    release = api_json(name + "/releases/tags/" + rec["latest"]["releaseTag"])
    assets = release_assets(rec, release, policy["releaseIds"][name], policy["repoIds"][name])
    require_asset_id_pins(assets, policy["assetIds"][name])
    require(sum(a["size"] for a in assets.values()) <= MAX_RELEASE, "release too large")
    metadata = api_json(name)
    require(metadata.get("id") == policy["repoIds"][name]
            and metadata.get("full_name") == repo, "substituted numeric repository")
    require(resolve_tag(name, release["tag_name"]) == release["target_commitish"],
            "Release tag source mismatch")
    ancestry = api_json(name + "/compare/" + release["target_commitish"] + "...main")
    require(ancestry.get("status") in ("identical", "ahead"), "source not on main")
    key = identity(policy, name, release)
    source_bytes = pinned_content(name, "config/extension.json", release["target_commitish"])
    config = strict_json(source_bytes)
    with tempfile.TemporaryDirectory(prefix="p1-release-") as tmp:
        folder = Path(tmp)
        obtain_assets(cache, folder, assets, repo, release["tag_name"])
        hashes = rehash_common_original(folder, assets, rec, name, release)
        structural = inspect_release_structure(folder, rec, name, release)
        common = {"schema": SCHEMA, "type": "release",
                  "extension": name, "releaseId": release["id"],
                  "repositoryId": policy["repoIds"][name],
                  "releaseIdentitySha256": key, "catalogCommit": policy["catalogCommitSha"],
                  "verifier": VERIFIER, "profile": original_profile(name, release),
                  "assetIds": {n: a["id"] for n, a in sorted(assets.items())},
                  "assetSha256": hashes, "allAssetsRehashed": len(hashes) == len(assets),
                  "allPgZipCrcVerified": len(structural) == 5,
                  "allPgSpdxGrypeStructured": len(structural) == 5,
                  "observedUntrustedProfiles": structural,
                  "decision": "PASS", "publicationAuthorized": False,
                  "distributionAuthorized": False}
        rows = {}
        for major in MAJORS:
            if not rec["postgresql"].get(major, {}).get("available"):
                continue
            row = rec["postgresql"][major]
            if (name, major) == BASELINE[:2]:
                rows[major] = row_receipt(name, major, policy, release, key, measured, {
                    "decision": "ALREADY_ACCEPTED", "reason": "2026-10-17 sealed PG14 bridge; not recounted"}, origin="prior-formal-bridge")
                continue
            observed = None
            try:
                src = immutable_source(config, int(major), rec)
                zp = folder / row["asset"]
                sbom = folder / row["evidence"]["sbom"]["asset"]
                grype = folder / row["evidence"]["vulnerabilityReport"]["asset"]
                pkg = inspect_package(zp, sbom, grype, repository=repo, major=int(major),
                                      immutable_packaging_sha=release["target_commitish"],
                                      source=src)
                observed = {"signerSha": pkg["signerSha"],
                            "runId": pkg["runId"], "runAttempt": pkg["runAttempt"]}
                run_id, attempt = pkg["runId"], pkg["runAttempt"]
                run = api_json(name + "/actions/runs/" + str(run_id))
                signed_run(run, repo=repo, repo_id=policy["repoIds"][name],
                           packaging_sha=release["target_commitish"],
                           run_id=run_id, attempt=attempt)
                jobs = fetch_jobs(name, run_id, major)
                require(pkg["signerSha"] in policy["trustedSignerShas"],
                        "unapproved signer workflow SHA")
                require(root is not None and measured.get("binarySha256"),
                        "BLOCKED: official gh/TUF trust bootstrap unavailable")
                attestdir = folder / ("attest-" + major)
                attestdir.mkdir()
                gh_read("attestation", "download", str(zp.resolve()), "--repo", repo,
                        cwd=attestdir)
                bname = "sha256:" + hashes[row["asset"]] + ".jsonl"
                b = attestdir / bname
                if not b.is_file():
                    b = attestdir / bname.replace("sha256:", "sha256-")
                require(b.is_file() and not b.is_symlink(), "missing original Sigstore bundle")
                bundle_hash = sha(b)
                proof = verify_sigstore_offline(
                    zp, pkg["sbom"], repo=repo, repo_id=policy["repoIds"][name],
                    packaging_sha=release["target_commitish"], signer_sha=pkg["signerSha"],
                    run_id=run_id, attempt=attempt, root_path=root,
                    root_sha=policy["rootSha256"], bundles={
                        PROVENANCE: (b, bundle_hash), SPDX: (b, bundle_hash)})
                rows[major] = row_receipt(name, major, policy, release, key, measured, {
                    "decision": "PASS_CANDIDATE", "integrityVerified": True,
                    "signatureVerified": proof["signatureVerified"],
                    "runId": run_id, "runAttempt": attempt,
                    "observedUnsignedPackage": observed,
                    "signatureProof": {"bundleSha256": bundle_hash,
                                       "signerSha": pkg["signerSha"], **jobs}})
            except (Denied, OSError, KeyError, TypeError, ValueError) as exc:
                why = str(exc)[:240]
                rows[major] = row_receipt(name, major, policy, release, key, measured, {
                    "decision": "BLOCKED" if why.startswith("BLOCKED:") else "DENY",
                    "integrityVerified": True, "reason": why,
                    "observedUnsignedPackage": observed})
        return common, rows


def run(policy, cache, output):
    require(set(policy["repoIds"]) == set(NAMES) and
            set(policy["releaseIds"]) == set(NAMES) and
            set(policy["assetIds"]) == set(NAMES) and
            policy["approvedMajors"] == [14, 15, 16, 17, 18],
            "incomplete/unsupported immutable fleet policy")
    output.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    measured = {}
    root = None
    with tempfile.TemporaryDirectory(prefix="p1-trust-") as td:
        # Never pass an Actions token to unpinned gh. Only a SHA-pinned,
        # previously authenticated executable can GET or verify material.
        try:
            measured = require_gh(policy)
        except (Denied, OSError, TypeError, ValueError, KeyError) as exc:
            measured = {"bootstrapBlocker": str(exc)[:240]}
        if not measured.get("binarySha256"):
            records = None
            global_reason = measured["bootstrapBlocker"]
        else:
            try:
                root = fresh_root(policy, Path(td) / "trusted_root.jsonl")
            except (Denied, OSError, TypeError, ValueError, KeyError) as exc:
                measured["bootstrapBlocker"] = str(exc)[:240]
            # A trusted gh may safely acquire original public bytes even if
            # the external TUF root gate cannot be established.
            try:
                records = get_catalog(policy)
            except (Denied, OSError, TypeError, ValueError, KeyError) as exc:
                records = None
                global_reason = str(exc)[:240]
        receipts = {}
        candidates = []
        for name in NAMES:
            try:
                require(records is not None, global_reason if records is None else "")
                common, rows = handle_release(name, records[name], policy, cache, root, measured)
                (output / (name + "-release.json")).write_bytes(json_bytes(common))
            except (Denied, OSError, KeyError, TypeError, ValueError) as exc:
                rows = {major: {
                    "schema": SCHEMA, "type": "row", "extension": name,
                    "pgMajor": int(major), "decision": "BLOCKED",
                    "reason": str(exc)[:240], "integrityVerified": False,
                    "signatureVerified": False, "formalAcceptedByThisRun": False,
                    "publicationAuthorized": False, "distributionAuthorized": False
                } for major in MAJORS}
                if name == "pg_bigm":
                    rows["14"]["decision"] = "ALREADY_ACCEPTED"
                    rows["14"]["reason"] = "previous exact sealed bridge accepted; no new inspection"
            for major, receipt in rows.items():
                (output / (name + "-pg" + major + ".json")).write_bytes(json_bytes(receipt))
                receipts[(name, major)] = receipt
                if receipt["decision"] == "PASS_CANDIDATE":
                    candidates.append([name, int(major)])
        require(len(receipts) == 70, "incomplete 70-row receipt inventory")
        report = {
            "schema": SCHEMA, "type": "summary",
            "asOf": datetime.now(timezone.utc).isoformat(), "catalogCommit": policy["catalogCommitSha"],
            "verificationMode": "original-release-real-bytes-and-genuine-cryptography",
            "verifiedCandidatesNotFormallyAdmitted": candidates,
            "formalAcceptedBaseline": [dict(extension="pg_bigm", pgMajor=14,
                                            repoId=BASELINE[2], releaseId=BASELINE[3],
                                            assetId=BASELINE[4])],
            "formalP1Accepted": 1, "formalP1Total": 70,
            "historicalSourceAccepted": 0, "historicalSourceTotal": 40,
            "batchDecisions": {x: sum(r["decision"] == x for r in receipts.values())
                               for x in ("ALREADY_ACCEPTED", "PASS_CANDIDATE",
                                         "DENY", "BLOCKED")},
            "p1": "BLOCKED", "p2": "NO-GO", "fleetComplete": False,
            "publicationAuthorized": False, "distributionAuthorized": False,
            "formalDistribution": "DENY",
        }
        (output / "summary.json").write_bytes(json_bytes(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        policy = policy_load(args.policy)
        result = run(policy, args.cache, args.output)
        print(json.dumps(result, sort_keys=True))
        return (0 if result["batchDecisions"]["BLOCKED"] == 0 and
                result["batchDecisions"]["DENY"] == 0 else 2)
    except (Denied, OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"decision": "DENY", "publicationAuthorized": False,
                          "reason": str(exc)[:240]}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
