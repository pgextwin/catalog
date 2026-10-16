#!/usr/bin/env python3
"""Issue #112 P1 read-only audit runner: explicit online GET or networkless offline.

Does not generate a trusted root, a signed manifest, a distribution bundle,
a publication receipt, a PR, a Release, a tag, or a CI Dispatch. The local
snapshot is staging DATA, not a self-authenticating offline trust anchor.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import base64
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from zipfile import ZipFile

from distribution_manifest_v1 import Denied, require, strict_json, safe_component
from distribution_release_verify_p1 import (
    PROVENANCE, SPDX, fleet_counts, sha, release_assets, rehash_release,
    lifecycle_status,
    require_asset_id_pins, MAX_RELEASE,
    verified_catalog, immutable_source, inspect_package, signed_run,
    verify_sigstore_offline, parse_sums,
)

HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
MAX_API_BYTES = 8 * 1024 * 1024


def gh_read(*args, cwd=None):
    """Allowlisted GitHub CLI GET/download only, no shell or write endpoint."""
    require(args and (
        (args[0] == "api" and len(args) == 2 and
         re.fullmatch(r"repos/pgextwin/[a-z][a-z0-9_]*/(?:compare/[a-f0-9]{40}\.\.\.main|contents/(?:index\.json|extensions/[a-z][a-z0-9_]*\.json|config/extension\.json)\?ref=[a-f0-9]{40}|releases/tags/[A-Za-z0-9_.-]+|git/ref/tags/[A-Za-z0-9_.-]+|git/tags/[a-f0-9]{40}|actions/runs/[1-9][0-9]*)", args[1]))
        or (args[0] == "api" and len(args) == 2 and
            re.fullmatch(r"repos/pgextwin/[a-z][a-z0-9_]*", args[1]))
        or (args[:2] == ("release", "download") and len(args) == 7 and
            args[3] == "--repo" and args[5] == "--dir"
            and re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", args[4])
            and re.fullmatch(r"[A-Za-z0-9_.-]+", args[2]))
        or (args[:2] == ("attestation", "download") and len(args) == 5
            and args[3] == "--repo"
            and re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", args[4]))
    ), "unallowlisted non-GET GitHub CLI operation")
    try:
        result = subprocess.run(("gh",) + args, capture_output=True, text=True,
                                timeout=300, check=False, cwd=cwd,
                                env={**os.environ, "GH_NO_UPDATE_NOTIFIER": "1",
                                     "GH_PROMPT_DISABLED": "1"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Denied("GitHub GET unavailable or timed out") from exc
    require(result.returncode == 0, "GitHub GET-only operation failed; no trust decision")
    require(len(result.stdout.encode("utf-8")) < MAX_API_BYTES,
            "unexpected oversized GitHub response")
    return result.stdout


def api_json(repo_suffix):
    return strict_json(gh_read("api", "repos/pgextwin/" + repo_suffix))


def pinned_content(repo, path, commit):
    require(HEX40.fullmatch(commit), "untrusted immutable content SHA")
    data = api_json(repo + "/contents/" + path + "?ref=" + commit)
    require(data.get("encoding") == "base64" and type(data.get("content")) is str,
            "immutable GitHub content not base64")
    try:
        return base64.b64decode(data["content"], validate=False)
    except (ValueError, UnicodeError) as exc:
        raise Denied("invalid immutable GitHub content") from exc


def resolve_tag(repo, tag):
    ref = api_json(repo + "/git/ref/tags/" + tag)
    obj = ref.get("object") or {}
    for _ in range(3):
        typ, commit = obj.get("type"), obj.get("sha")
        require(type(commit) is str and HEX40.fullmatch(commit), "invalid Release tag SHA")
        if typ == "commit":
            return commit
        require(typ == "tag", "unsupported tag type")
        obj = (api_json(repo + "/git/tags/" + commit).get("object") or {})
    raise Denied("tag recursion exceeds policy")


def policy_load(path):
    """User must authenticate the digest and origin of THIS policy externally."""
    p = strict_json(path.read_bytes())
    require(type(p) is dict and p.get("schemaVersion") == "pgextwin-p1-readonly-policy/v1"
            and p.get("signerRepositoryId") == 1405931353
            and type(p.get("catalogCommitSha")) is str
            and HEX40.fullmatch(p["catalogCommitSha"])
            and type(p.get("catalogDigests")) is dict
            and type(p.get("repoIds")) is dict
            and type(p.get("releaseIds")) is dict
            and type(p.get("assetIds")) is dict
            and type(p.get("pgEol")) is dict
            and type(p.get("trustedSignerShas")) is list
            and p["trustedSignerShas"]
            and all(type(s) is str and HEX40.fullmatch(s) for s in p["trustedSignerShas"])
            and type(p.get("approvedMajors")) is list
            and p["approvedMajors"] == sorted(set(p["approvedMajors"]), key=int)
            and all(type(v) is int and v > 0 for v in p["approvedMajors"])
            and type(p.get("rootSha256")) is str and HEX64.fullmatch(p["rootSha256"]),
            "incomplete separately authenticated policy")
    return p


def source_path(root, name):
    return root / "sources" / (safe_component(name) + ".json")


def asset_directory(root, name):
    return root / "releases" / safe_component(name) / "assets"


def validate_run_pair(root, name, run_id):
    """A local snapshot needs independently authenticated provenance for trust."""
    path = root / "runs" / (safe_component(name) + ".json")
    require(path.is_file(), "no immutable run snapshot")
    run = strict_json(path.read_bytes())
    require(run.get("id") == run_id, "wrong run snapshot")
    return run


def materialize_online(root, policy):
    """Explicit GET-only capture; downloaded bytes never automatically trusted."""
    commit = policy["catalogCommitSha"]
    signer_meta = api_json("build")
    require(signer_meta.get("full_name") == "pgextwin/build"
            and signer_meta.get("id") == policy["signerRepositoryId"],
            "reusable signer numeric GitHub repository ID changed")
    relation = api_json("catalog/compare/" + commit + "...main")
    require(relation.get("status") in ("identical", "ahead"),
            "pinned Catalog commit not on protected main ancestry")
    index = pinned_content("catalog", "index.json", commit)
    parsed = strict_json(index)
    names = parsed.get("extensions") or []
    require(type(names) is list and names == sorted(set(names)),
            "Catalog extension index invalid")
    (root/"catalog"/"extensions").mkdir(parents=True, exist_ok=True)
    (root/"catalog"/"index.json").write_bytes(index)
    for name in names:
        safe_component(name)
        blob = pinned_content("catalog", "extensions/" + name + ".json", commit)
        (root/"catalog"/"extensions"/(name+".json")).write_bytes(blob)
        record = strict_json(blob)
        repo = "pgextwin/" + name
        metadata = api_json(name)
        require(metadata.get("id") == policy["repoIds"].get(name)
                and metadata.get("full_name") == repo,
                "source repository numeric ID mismatch")
        release = api_json(name + "/releases/tags/" + record["latest"]["releaseTag"])
        require(release.get("id") == policy["releaseIds"].get(name),
                "formal Release numeric ID mismatch")
        require(resolve_tag(name, release["tag_name"]) == release["target_commitish"],
                "formal Release tag no longer resolves to source SHA")
        ancestry = api_json(name + "/compare/" + release["target_commitish"] + "...main")
        require(ancestry.get("status") in ("identical", "ahead"),
                "formal Release packaging SHA not on main ancestry")
        meta_assets = release_assets(record, release, policy["releaseIds"][name],
                                     policy["repoIds"][name])
        require_asset_id_pins(meta_assets, policy["assetIds"][name])
        require(sum(asset["size"] for asset in meta_assets.values()) <= MAX_RELEASE,
                "Release would exceed maximum download budget")
        (root/"releases"/name).mkdir(parents=True, exist_ok=True)
        (root/"releases"/name/"release.json").write_text(json.dumps(release),encoding="utf-8")
        (root/"sources").mkdir(parents=True, exist_ok=True)
        src = pinned_content(name, "config/extension.json", release["target_commitish"])
        source_path(root, name).write_bytes(src)
        folder = asset_directory(root, name)
        folder.mkdir(parents=True, exist_ok=True)
        gh_read("release", "download", release["tag_name"], "--repo", repo, "--dir", str(folder))
        (root/"runs").mkdir(parents=True, exist_ok=True)
        downloaded_assets = release_assets(record, release, policy["releaseIds"][name],
                                           policy["repoIds"][name])
        require_asset_id_pins(downloaded_assets, policy["assetIds"][name])
        verified_hashes = rehash_release(folder, downloaded_assets, record)
        run_ids = set()
        for pg, info in record["postgresql"].items():
            if info.get("available") is not True:
                continue
            zip_file = folder/info["asset"]
            with ZipFile(zip_file) as archive:
                matches = [i for i in archive.infolist() if i.filename == "PACKAGE-INFO.json"]
                require(len(matches) == 1 and matches[0].file_size <= 262144,
                        "untrusted binary package metadata")
                pkg = strict_json(archive.read("PACKAGE-INFO.json"))
            run = (pkg.get("workflowRun") or {}).get("id")
            require(type(run) is int and run > 0, "missing formal Promotion run")
            run_ids.add(run)
            attest_dir = root/"attestations"/name
            attest_dir.mkdir(parents=True, exist_ok=True)
            gh_read("attestation", "download", str(zip_file.resolve()),
                    "--repo", repo, cwd=attest_dir)
            digest = verified_hashes[info["asset"]]
            candidates = [attest_dir/("sha256:"+digest+".jsonl"),
                          attest_dir/("sha256-"+digest+".jsonl")]
            present = [p for p in candidates if p.is_file() and not p.is_symlink()]
            require(len(present) == 1, "missing/ambiguous downloaded attestation bundle")
            present[0].rename(attest_dir/(info["asset"]+".jsonl"))
        require(len(run_ids) == 1, "mixed original Release run IDs")
        run_id = next(iter(run_ids))
        a = api_json(name + "/actions/runs/" + str(run_id))
        b = api_json(name + "/actions/runs/" + str(run_id))
        require(a == b, "run metadata changed between GETs")
        (root/"runs"/(name+".json")).write_text(json.dumps(a),encoding="utf-8")
    return names


def read_snapshot(root, policy):
    ib = (root/"catalog"/"index.json").read_bytes()
    names = strict_json(ib)["extensions"]
    blobs = {n: (root/"catalog"/"extensions"/(safe_component(n)+".json")).read_bytes()
             for n in names}
    records = verified_catalog(ib, blobs, policy["catalogDigests"],
                               policy["catalogCommitSha"])
    require(set(policy["pgEol"]) == {str(m) for m in policy["approvedMajors"]},
            "incomplete independent PG lifecycle registry")
    require(set(policy["repoIds"]) == set(records)
            and set(policy["releaseIds"]) == set(records)
            and set(policy["assetIds"]) == set(records),
            "incomplete numeric identity policy")
    return records


def audit_snapshot(root, policy, trust_root, *, allow_sigstore):
    records = read_snapshot(root, policy)
    outcomes = {}
    supported = {(n, pg) for n, r in records.items() for pg, v in r["postgresql"].items()
                 if v.get("available") is True}
    for name, rec in records.items():
        repo = "pgextwin/" + name
        try:
            release = strict_json((root/"releases"/name/"release.json").read_bytes())
            assets = release_assets(rec, release, policy["releaseIds"][name],
                                    policy["repoIds"][name])
            require_asset_id_pins(assets, policy["assetIds"][name])
            hashes = rehash_release(asset_directory(root, name), assets, rec)
            config = strict_json(source_path(root, name).read_bytes())
        except (Denied, OSError, KeyError, ValueError) as exc:
            for pair in supported:
                if pair[0] == name:
                    outcomes[pair] = {"integrityVerified": False, "signatureVerified": False,
                                      "reason": str(exc)[:180]}
            continue
        attempt_by_release = set()
        for pg, info in rec["postgresql"].items():
            if info.get("available") is not True:
                continue
            pair = (name, pg)
            try:
                require(int(pg) in policy["approvedMajors"],
                        "PG major not independently authorized")
                source = immutable_source(config, int(pg), rec)
                zip_file = asset_directory(root, name)/info["asset"]
                sbom = asset_directory(root, name)/info["evidence"]["sbom"]["asset"]
                grype = asset_directory(root, name)/info["evidence"]["vulnerabilityReport"]["asset"]
                pkg = inspect_package(zip_file, sbom, grype, repository=repo,
                                      major=int(pg), immutable_packaging_sha=release["target_commitish"],
                                      source=source)
                require(pkg["signerSha"] in policy["trustedSignerShas"],
                        "unknown independently approved signer commit")
                attempt_by_release.add((pkg["runId"], pkg["runAttempt"]))
                require(len(attempt_by_release) == 1, "mixed Release run IDs/attempts")
                run = validate_run_pair(root, name, pkg["runId"])
                signed_run(run, repo=repo, repo_id=policy["repoIds"][name],
                           packaging_sha=release["target_commitish"], run_id=pkg["runId"],
                           attempt=pkg["runAttempt"])
                outcomes[pair] = {"integrityVerified": True, "signatureVerified": False,
                                  "reason": "Sigstore proof not attempted"}
                if not allow_sigstore:
                    continue
                # Deliberately no discovery of trusted roots inside the snapshot.
                # P1 must use independently pinned trusted-root material.
                bundle = root/"attestations"/name/(info["asset"]+".jsonl")
                require(bundle.is_file(), "missing downloaded SLSA/SPDX proof bundle")
                pair_bundle = (bundle, sha(bundle))
                verdict = verify_sigstore_offline(
                    zip_file, pkg["sbom"], repo=repo, repo_id=policy["repoIds"][name],
                    packaging_sha=release["target_commitish"], signer_sha=pkg["signerSha"],
                    run_id=pkg["runId"], attempt=pkg["runAttempt"],
                    root_path=trust_root, root_sha=policy["rootSha256"],
                    bundles={PROVENANCE: pair_bundle, SPDX: pair_bundle})
                outcomes[pair] = verdict
            except (Denied, OSError, KeyError, TypeError, ValueError) as exc:
                previous = outcomes.get(pair) or {}
                outcomes[pair] = {"integrityVerified": previous.get("integrityVerified") is True,
                                  "signatureVerified": False,
                                  "reason": str(exc)[:180]}
    report = fleet_counts(records, outcomes)
    today = datetime.now(timezone.utc).date().isoformat()
    status_counts = {"maintained": 0, "historical": 0, "unsupported": 0}
    for name, rec in records.items():
        for major, row in rec["postgresql"].items():
            status = lifecycle_status(int(major), as_of_utc=today,
                eol_by_major=policy["pgEol"], approved_majors=policy["approvedMajors"])
            status_counts[status] += 1
    report["lifecycleCoverage"] = status_counts
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="nonpublishing read-only P1 audit")
    parser.add_argument("--policy", type=Path, required=True,
                        help="separately authenticated immutable SHA/Repo/Release/trust-root policy")
    parser.add_argument("--snapshot", type=Path, required=True,
                        help="private local directory, NOT a publishable bundle")
    parser.add_argument("--trusted-root", type=Path,
                        help="trusted root received and authenticated independently")
    parser.add_argument("--online-get", action="store_true",
                        help="explicitly fetch GitHub metadata/assets, never modify GitHub")
    args = parser.parse_args(argv)
    result = {"complete": False, "publicationAuthorized": False,
              "decision": "DENY", "reason": "not started"}
    try:
        policy = policy_load(args.policy)
        require(args.snapshot != args.policy and not args.snapshot.is_symlink(),
                "unsafe snapshot destination")
        if args.online_get:
            args.snapshot.mkdir(parents=True, exist_ok=True)
            materialize_online(args.snapshot, policy)
        require(args.trusted_root is not None, "external root absent")
        result = audit_snapshot(args.snapshot, policy, args.trusted_root,
                                allow_sigstore=True)
        result["decision"] = "NONPUBLISHING_VALIDATION_ONLY" if result["complete"] else "DENY"
        # Still not permission to publish even if cryptographic evidence is complete.
        result["publicationAuthorized"] = False
    except (Denied, OSError, KeyError, ValueError, TypeError) as exc:
        result["reason"] = str(exc)[:200]
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("complete") is True else 2


if __name__ == "__main__":
    sys.exit(main())
