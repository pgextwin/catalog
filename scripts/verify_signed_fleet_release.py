#!/usr/bin/env python3
"""Read-only, fail-closed public signed Release verifier for all 14 extensions.

This is NOT a publisher or a Catalog merger. The verified Catalog record is
returned only after all download hashes, ZIP identities, manifest pins,
attestations, and manual main-Promotion provenance independently pass.
Historical release/* publishers are deliberately not accepted as a new input.
"""
from __future__ import annotations

import argparse
import base64
from datetime import date
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
        ALLOWED, Denied, SUFFIXES, majors, map_verified_release, require, source_map,
    )
else:
    from verified_release_record import (
        ALLOWED, Denied, SUFFIXES, majors, map_verified_release, require, source_map,
    )

SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
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
    wf = str(run.get("path") or "").split("@", 1)[0]
    operator = (run.get("actor") or {}).get("login", "")
    require(run.get("head_sha") == source_commit
            and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and wf == repo + "/.github/workflows/promote.yml",
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
        source = dict(src[major], repository=ALLOWED[name])
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


def generate(extension, tag, record, today=None):
    require(extension in ALLOWED, "extension not on exact 14-repository allowlist")
    repo = "pgextwin/" + extension
    require(isinstance(tag, str) and re.fullmatch(r"v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*", tag),
            "invalid formal Release tag")
    require(record.is_file() and record.name == extension + ".json"
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
    active = required_majors(manifest, lifecycle, today or date.today())
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
            gh("attestation", "verify", zipped, "--repo", repo,
               "--signer-workflow", SIGNER)
            gh("attestation", "verify", zipped, "--repo", repo,
               "--signer-workflow", SIGNER,
               "--predicate-type", "https://spdx.dev/Document/v2.3")
    original = json.loads(record.read_text(encoding="utf-8"))
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
        print(json.dumps(audit, sort_keys=True))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, IndexError,
            BadZipFile, subprocess.SubprocessError) as exc:
        print("FLEET CATALOG EVIDENCE DENIED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
