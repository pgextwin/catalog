#!/usr/bin/env python3
"""Read-only, fail-closed public signed Release verifier for approved Catalog identities.

This is NOT a publisher or a Catalog merger. The verified Catalog record is
returned only after all download hashes, ZIP identities, manifest pins,
attestations, and manual main-Promotion provenance independently pass.
Historical release/* publishers are deliberately not accepted as a new input.
"""
from __future__ import annotations

import argparse
import base64
from datetime import date, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from zipfile import ZipFile, BadZipFile

if __package__:
    from .verified_release_record import (
        INTAKE_ALLOWED, FIRST_RELEASE_SOURCES, Denied, SUFFIXES, majors, map_verified_release, require, source_map,
        seed_verified_first_release,
    )
else:
    from verified_release_record import (
        INTAKE_ALLOWED, FIRST_RELEASE_SOURCES, Denied, SUFFIXES, majors, map_verified_release, require, source_map,
        seed_verified_first_release,
    )

SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
# Wave3 FIRST Release only: require the exact immutable Signer currently
# referenced by its shared manual promotion source. Historical 14-member
# Catalog intake is intentionally unchanged.
WAVE3_SIGNER_SHA = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
PROVENANCE = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SUM_LINE = re.compile(r"^([0-9a-f]{64})  (?:\./)?([A-Za-z0-9_.-]+)$")


def gh(*args):
    process = subprocess.run(("gh",) + args, text=True, capture_output=True)
    require(process.returncode == 0,
            "GitHub verification failed: " + " ".join(args[:3]) +
            " " + process.stderr[:200])
    return process.stdout


def api(path):
    return json.loads(gh("api", path))


def pinned_json(repo, commit, path):
    require(bool(HEX40.fullmatch(commit)), "invalid immutable source SHA")
    data = api("repos/" + repo + "/contents/" + path + "?ref=" + commit)
    require(data.get("encoding") == "base64" and isinstance(data.get("content"), str),
            "immutable source file unavailable")
    return json.loads(base64.b64decode(data["content"]).decode("utf-8"))


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def required_majors(manifest, lifecycle, today):
    configured = set(majors(manifest))
    rows = lifecycle.get("postgresql")
    require(isinstance(rows, list) and len(rows) >= 5, "missing PG lifecycle")
    eols = {}
    for row in rows:
        m = row.get("major")
        require(type(m) is int and m not in eols
                and isinstance(row.get("eol"), str), "ambiguous PG lifecycle")
        eols[m] = date.fromisoformat(row["eol"])
    active = sorted(m for m in configured if m in eols and eols[m] >= today)
    require(bool(active), "no maintained PostgreSQL target")
    return active


def published_release_day(release):
    """Use immutable Release publication time, not the later Catalog sync date.

    A pre-EOL PG14 Release can still be synchronized after PG14 becomes
    historical; its already-published signed PG14 asset is not an extra file.
    """
    raw = release.get("published_at")
    require(isinstance(raw, str), "missing Release publication timestamp")
    try:
        published = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Denied("invalid Release publication timestamp") from exc
    require(published.tzinfo is not None,
            "Release publication timestamp missing timezone")
    return published.date()


def check_source_package(pkg, repo, source_commit, major, source):
    """Fail closed on exact per-PG upstream and packaging/run identities."""
    require(type(pkg) is dict and pkg.get("schemaVersion") == 1
            and pkg.get("buildMode") == "release-attested", "unsigned build mode")
    package = pkg.get("package", {})
    require(package.get("name") == repo.split("/")[-1]
            and package.get("platform") == "windows"
            and package.get("architecture") == "x64", "wrong package identity")
    upstream = pkg.get("upstream", {})
    require(upstream.get("repository") == source["repository"]
            and upstream.get("ref") == source["ref"]
            and upstream.get("version") == source["version"]
            and upstream.get("commit") == source["commit"],
            "upstream/ref/version/full-SHA mismatch for PG" + str(major))
    packaging = pkg.get("source", {})
    require(packaging.get("packagingRepository") == repo
            and packaging.get("packagingCommit") == source_commit,
            "wrong packaging repository/main SHA")
    require(pkg.get("postgresql", {}).get("major") == major,
            "wrong PostgreSQL major in PACKAGE-INFO")
    run = pkg.get("workflowRun", {})
    require(type(run.get("id")) is int and run["id"] > 0
            and run.get("ref") == "refs/heads/main"
            and run.get("event") == "workflow_dispatch",
            "package not produced by an operator-only main Promotion")
    return run["id"]


def verify_main_run(repo, run_id, source_commit):
    run = api("repos/" + repo + "/actions/runs/" + str(run_id))
    # GitHub REST Actions runs return ".github/workflows/promote.yml" as
    # `path` (not "owner/repo/.github/workflows/promote.yml"). Accept the
    # exact repository-relative workflow, never an arbitrary suffixed path.
    wf = run.get("path")
    operator = (run.get("actor") or {}).get("login", "")
    require(run.get("head_sha") == source_commit
            and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and wf == ".github/workflows/promote.yml",
            "untrusted formal Promotion workflow/SHA/event")
    require(isinstance(operator, str) and operator and not operator.endswith("[bot]"),
            "no identified human operator for PUBLISH")
    # A previous Draft lookup bug produced one historically failed run.
    # Do not silently generalize that exception to new Releases.
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "formal Promotion did not finish successfully")


def verify_release_tag(repo, tag, source_commit):
    ref = api("repos/" + repo + "/git/ref/tags/" + tag)
    obj = ref.get("object") or {}
    for _ in range(3):
        typ, sha = obj.get("type"), obj.get("sha")
        require(isinstance(sha, str) and bool(HEX40.fullmatch(sha)),
                "invalid Git tag SHA")
        if typ == "commit":
            require(sha == source_commit, "tag does not resolve to packaging SHA")
            return
        require(typ == "tag", "unsupported Git tag object")
        obj = api("repos/" + repo + "/git/tags/" + sha).get("object") or {}
    raise Denied("too many tag-object indirections")


def verify_payload(folder, release, manifest, contract, source_commit, active):
    """Validate downloaded bytes and ZIP metadata; attestations are checked by caller."""
    name = manifest["name"]
    repo = "pgextwin/" + name
    files = {p.name: p for p in folder.iterdir() if p.is_file()}
    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == len({a.get("name") for a in assets}),
            "duplicate/missing public Release assets")
    asset_map = {a["name"]: a for a in assets}
    require(set(files) == set(asset_map) and "SHA256SUMS.txt" in files,
            "downloaded assets do not match published Release")
    lines = files["SHA256SUMS.txt"].read_text(encoding="utf-8-sig").splitlines()
    sums = {}
    for line in lines:
        match = SUM_LINE.fullmatch(line)
        require(match is not None and match.group(2) not in sums,
                "malformed/duplicate checksum")
        sums[match.group(2)] = match.group(1)
    require(set(sums) == set(files) - {"SHA256SUMS.txt"},
            "partial or extra SHA256SUMS entry")
    for fn, path in files.items():
        a = asset_map[fn]
        require(a.get("state") == "uploaded"
                and a.get("digest") == "sha256:" + digest(path),
                "GitHub digest or downloaded bytes changed: " + fn)
        if fn != "SHA256SUMS.txt":
            require(digest(path) == sums[fn], "checksum file differs: " + fn)
    src = source_map(manifest)
    expected = {"SHA256SUMS.txt"}
    run_id = None
    for major in active:
        source = dict(src[major], repository=INTAKE_ALLOWED[name])
        stem = name + "-" + source["ref"] + "-pg" + str(major) + "-windows-x64"
        expected.update(stem + suf for suf in SUFFIXES)
        zip_path = files[stem + ".zip"]
        with ZipFile(zip_path) as zf:
            require(zf.namelist().count("PACKAGE-INFO.json") == 1,
                    "missing or duplicate immutable package metadata")
            pkg = json.loads(zf.read("PACKAGE-INFO.json").decode("utf-8-sig"))
            # Optional pg_partman BGW must never be asserted without an actual DLL.
            if name == "pg_partman":
                bgw = contract["runtimeRequirements"].get("backgroundWorker")
                dll = "lib/pg_partman_bgw.dll"
                if bgw:
                    require(zf.namelist().count(dll) == 1
                            and zf.getinfo(dll).file_size >= 10000
                            and pkg.get("toolchain", {}).get("compiler") == "MSVC",
                            "optional BGW not proven by an actual MSVC DLL")
                else:
                    require(dll not in zf.namelist(), "unexpected BGW DLL in SQL-only package")
        ident = check_source_package(pkg, repo, source_commit, major, source)
        run_id = run_id or ident
        require(run_id == ident, "mixed build workflow run IDs")
        spdx = json.loads(files[stem + ".spdx.json"].read_text(encoding="utf-8-sig"))
        grype = json.loads(files[stem + ".vulnerabilities.json"].read_text(encoding="utf-8-sig"))
        require(spdx.get("spdxVersion") == "SPDX-2.3"
                and isinstance(grype.get("matches"), list), "invalid SPDX or Grype report")
    require(set(files) == expected, "missing/extra PG-major Release assets")
    return asset_map, sums, run_id



def unique_json_keys(pairs):
    """Reject conflicting/duplicated keys inside a signed predicate."""
    item = {}
    for key, value in pairs:
        require(key not in item, "duplicate key in attestation verification")
        item[key] = value
    return item


def validate_wave3_verified_attestation(raw, *, predicate, zip_name, zip_sha,
                                        expected_spdx=None):
    """Consume ONLY JSON from a successful real gh attestation verify call.

    This parser alone proves no cryptography: verification of Signer, source,
    predicate and GitHub trust roots is performed by the strict CLI call.
    Exactly one verified claim must bind the public ZIP digest; the signed
    SPDX predicate must be the downloaded, SHA-checked public SPDX document.
    """
    require(predicate in (PROVENANCE, SPDX)
            and isinstance(zip_name, str) and zip_name.endswith(".zip")
            and isinstance(zip_sha, str) and HEX64.fullmatch(zip_sha),
            "unknown signed Wave3 predicate or ZIP")
    try:
        claims = json.loads(raw, object_pairs_hook=unique_json_keys)
    except (TypeError, ValueError) as exc:
        raise Denied("malformed or duplicate-key signed Wave3 verification") from exc
    require(type(claims) is list and len(claims) == 1
            and type(claims[0]) is dict, "missing/ambiguous signed Wave3 claim")
    verified = claims[0].get("verificationResult")
    require(type(verified) is dict
            and type(verified.get("statement")) is dict,
            "missing GitHub-verified signed statement")
    statement = verified["statement"]
    subjects = statement.get("subject")
    require(statement.get("predicateType") == predicate
            and type(subjects) is list and len(subjects) == 1
            and type(subjects[0]) is dict
            and subjects[0].get("name") == zip_name
            and subjects[0].get("digest") == {"sha256": zip_sha},
            "signed statement does not bind exact public ZIP bytes")
    if predicate == SPDX:
        require(type(expected_spdx) is dict
                and expected_spdx.get("spdxVersion") == "SPDX-2.3"
                and statement.get("predicate") == expected_spdx,
                "public SPDX differs from verified signed SPDX predicate")
    else:
        require(type(statement.get("predicate")) is dict,
                "signed SLSA provenance predicate missing")


def verify_wave3_attestations(zip_path, spdx_path, *, repo, source_commit):
    """First Release: bind TWO signer-pinned claims to downloaded public bytes.

    This is Catalog-only read/verification; it never issues PUBLISH or writes
    a Release. Existing 14-extension verification retains its historical route.
    """
    require(isinstance(source_commit, str) and HEX40.fullmatch(source_commit)
            and repo in {"pgextwin/" + n for n in FIRST_RELEASE_SOURCES},
            "untrusted first-Release signer/source identity")
    zip_sha, spdx_sha = digest(zip_path), digest(spdx_path)
    try:
        signed_spdx = json.loads(spdx_path.read_text(encoding="utf-8-sig"),
                                 object_pairs_hook=unique_json_keys)
    except (ValueError, TypeError) as exc:
        raise Denied("unreadable/duplicate-key published SPDX") from exc
    require(type(signed_spdx) is dict
            and signed_spdx.get("spdxVersion") == "SPDX-2.3",
            "invalid published SPDX identity")
    for predicate in (PROVENANCE, SPDX):
        # gh performs the cryptographic verification. Each pinned flag is a
        # trust constraint; do not accept the JSON result without zero exit.
        verified = gh(
            "attestation", "verify", str(zip_path), "--repo", repo,
            "--signer-workflow", SIGNER, "--signer-digest", WAVE3_SIGNER_SHA,
            "--source-digest", source_commit, "--source-ref", "refs/heads/main",
            "--predicate-type", predicate, "--format", "json")
        validate_wave3_verified_attestation(
            verified, predicate=predicate, zip_name=zip_path.name,
            zip_sha=zip_sha, expected_spdx=signed_spdx if predicate == SPDX
            else None)
        require(digest(zip_path) == zip_sha and digest(spdx_path) == spdx_sha,
                "public ZIP/SPDX bytes changed during signature verification")


def deny_catalog_rollback(existing, release):
    """A valid old signature is not permission to replace newer public Catalog state."""
    current = (existing.get("latest") or {})
    old = current.get("publishedAt")
    if not old:
        return
    new = release.get("published_at")
    require(isinstance(new, str), "release lacks publication timestamp")
    try:
        old_date = datetime.fromisoformat(old.replace("Z", "+00:00"))
        new_date = datetime.fromisoformat(new.replace("Z", "+00:00"))
        require(old_date.tzinfo is not None and new_date.tzinfo is not None,
                "Catalog publication timestamp missing timezone")
    except (AttributeError, ValueError) as exc:
        raise Denied("invalid published timestamp in release/Catalog") from exc
    require(new_date >= old_date, "refuse to downgrade Catalog to an older Release")
    require(new_date != old_date or current.get("releaseTag") == release.get("tag_name"),
            "different Release tag shares same publication timestamp")


def generate(extension, tag, record):
    require(extension in INTAKE_ALLOWED, "extension not on exact Catalog verification allowlist")
    repo = "pgextwin/" + extension
    require(isinstance(tag, str) and re.fullmatch(r"v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*", tag),
            "invalid formal Release tag")
    require(record.name == extension + ".json"
            and record.parent.name == "extensions", "Catalog destination identity mismatch")
    release = api("repos/" + repo + "/releases/tags/" + tag)
    require(release.get("tag_name") == tag and release.get("draft") is False
            and release.get("prerelease") is False and release.get("published_at"),
            "not an existing publicly published stable Release")
    source_commit = release.get("target_commitish")
    require(isinstance(source_commit, str) and HEX40.fullmatch(source_commit),
            "Release target not an exact immutable packaging SHA")
    verify_release_tag(repo, tag, source_commit)
    ancestor = api("repos/" + repo + "/compare/" + source_commit + "...main")
    require(ancestor.get("status") in ("identical", "ahead"),
            "Release packaging commit is not trusted main ancestry")
    manifest = pinned_json(repo, source_commit, "config/extension.json")
    contract = pinned_json(repo, source_commit, "config/test-contract.json")
    lifecycle_raw = api("repos/pgextwin/build/contents/metadata/postgresql.json?ref=main")
    require(lifecycle_raw.get("encoding") == "base64", "PG lifecycle unavailable")
    lifecycle = json.loads(base64.b64decode(lifecycle_raw["content"]).decode("utf-8"))
    active = required_majors(manifest, lifecycle, published_release_day(release))
    require(manifest.get("name") == extension
            and contract.get("extension") == extension
            and contract.get("contractVersion") == 2, "wrong immutable source/contract")
    with tempfile.TemporaryDirectory() as tmp:
        gh("release", "download", tag, "--repo", repo, "--dir", tmp)
        folder = Path(tmp)
        assets, sums, run_id = verify_payload(folder, release, manifest, contract,
                                               source_commit, active)
        verify_main_run(repo, run_id, source_commit)
        for major in active:
            stem = extension + "-" + source_map(manifest)[major]["ref"] + "-pg" + str(major) + "-windows-x64"
            zipped = str(folder / (stem + ".zip"))
            if extension in FIRST_RELEASE_SOURCES:
                verify_wave3_attestations(
                    Path(zipped), folder / (stem + ".spdx.json"),
                    repo=repo, source_commit=source_commit)
            else:
                # Historical 14-member intake contract is unchanged.
                gh("attestation", "verify", zipped, "--repo", repo,
                   "--signer-workflow", SIGNER)
                gh("attestation", "verify", zipped, "--repo", repo,
                   "--signer-workflow", SIGNER,
                   "--predicate-type", SPDX)
    # Existing records are updated. Only the three explicitly pre-registered
    # third-wave identities may be seeded on their FIRST genuinely signed,
    # public, independently verified Release. No placeholder is written.
    original = (json.loads(record.read_text(encoding="utf-8"))
                if record.is_file() else seed_verified_first_release(manifest, contract))
    deny_catalog_rollback(original, release)
    mapped = map_verified_release(original, release, manifest, contract,
                                assets, sums, source_commit, active)
    return mapped, {"status": "VERIFIED", "repository": repo, "tag": tag,
                    "packagingCommit": source_commit, "promotionRunId": run_id,
                    "postgresqlMajors": active, "assetCount": len(assets),
                    "recordChanged": mapped != original}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--record-output")
    args = parser.parse_args()
    try:
        record = Path("extensions") / (args.extension + ".json")
        mapped, audit = generate(args.extension, args.release_tag, record)
        if args.record_output:
            output = Path(args.record_output)
            require(output == record, "record output must be the exact Catalog extension path")
            if audit["recordChanged"]:
                output.write_text(json.dumps(mapped, indent=2, ensure_ascii=False) + "\n",
                                  encoding="utf-8")
        output_file = os.environ.get("GITHUB_OUTPUT")
        if output_file:
            with open(output_file, "a", encoding="utf-8") as output:
                output.write("changed=" + str(audit["recordChanged"]).lower() + "\n")
        print(json.dumps(audit, sort_keys=True))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, IndexError,
            BadZipFile, subprocess.SubprocessError) as exc:
        print("FLEET CATALOG EVIDENCE DENIED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
