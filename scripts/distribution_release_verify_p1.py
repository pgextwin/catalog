#!/usr/bin/env python3
"""P1 read-only Release bytes and genuine offline Sigstore verification.

Local fixtures are NOT authentication. Never calls Publisher or Catalog update.
Cryptographic status can only come from a successful real gh attestation verify
against an independently authenticated trusted-root digest.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess
from zipfile import ZipFile, BadZipFile

from distribution_manifest_v1 import Denied, require, strict_json, safe_component, verify_archive_members
from verify_signed_fleet_release import check_source_package

PROVENANCE = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
PREDICATES = (PROVENANCE, SPDX)
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
ISSUER = "https://token.actions.githubusercontent.com"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_RELEASE = 512 * 1024 * 1024


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verified_catalog(index_bytes, records_bytes, expected_digests, immutable_commit):
    """Externally authenticated SHA and file-digest pins are inputs, not outputs."""
    require(isinstance(immutable_commit, str) and HEX40.fullmatch(immutable_commit),
            "missing pinned Catalog commit")
    require(type(index_bytes) is bytes and type(expected_digests) is dict
            and hashlib.sha256(index_bytes).hexdigest() == expected_digests.get("index.json"),
            "Catalog index hash mismatch")
    index = strict_json(index_bytes)
    names = index.get("extensions")
    require(index.get("schemaVersion") == 2 and type(names) is list and names
            and all(type(n) is str and re.fullmatch(r"[a-z][a-z0-9_]*", n) for n in names)
            and names == sorted(set(names)), "invalid dynamic extension matrix")
    require(set(records_bytes) == set(names)
            and set(expected_digests) == {"index.json"} |
                 {"extensions/" + n + ".json" for n in names}, "incomplete Catalog snapshot")
    records = {}
    for name in names:
        blob = records_bytes[name]
        require(type(blob) is bytes and hashlib.sha256(blob).hexdigest() ==
                expected_digests["extensions/" + name + ".json"],
                "changed immutable record bytes")
        record = strict_json(blob)
        require(record.get("schemaVersion") == 2
                and record.get("name") == name
                and record.get("repository") == "pgextwin/" + name
                and record.get("architecture") == "x64", "Catalog source substitution")
        records[name] = record
    return records


def immutable_source(extension_config, major, record):
    """Only a trusted full-SHA source config may supply per-major upstream pins."""
    require(type(major) is int and major > 0, "invalid PG major")
    target = extension_config.get("postgresql", {})
    majors = target.get("majors")
    if majors is None and type(target.get("minMajor")) is int and type(target.get("maxMajor")) is int:
        majors = list(range(target["minMajor"], target["maxMajor"] + 1))
    require(type(majors) is list and major in majors
            and all(type(m) is int and m > 0 for m in majors)
            and len(set(majors)) == len(majors), "PG major unsupported")
    u = extension_config.get("upstream", {})
    require(extension_config.get("name") == record["name"]
            and u.get("repository") == record["upstream"].get("repository"),
            "upstream repo mismatch")
    p = u.get("perPostgresql", {}).get(str(major), u)
    c = record["upstream"].get("perPostgresql", {}).get(str(major), record["upstream"])
    require(p.get("version") == c.get("version")
            and ("ref" not in c or p.get("ref") == c["ref"])
            and isinstance(p.get("commit"), str) and HEX40.fullmatch(p["commit"])
            and isinstance(p.get("ref"), str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", p["ref"]),
            "upstream ref/version/full SHA mismatch")
    return dict(p, repository=u["repository"])


def release_assets(record, release, expected_release_id, expected_repo_id):
    """Numeric IDs supplied by separate authenticated API/policy, not release tag."""
    repo = record["repository"]
    require(type(expected_release_id) is int and expected_release_id > 0
            and type(expected_repo_id) is int and expected_repo_id > 0,
            "untrusted Release/repository numeric identity")
    require(release.get("id") == expected_release_id
            and release.get("tag_name") == record["latest"]["releaseTag"]
            and release.get("draft") is False and release.get("prerelease") is False
            and release.get("published_at") == record["latest"]["publishedAt"]
            and release.get("html_url") == record["latest"]["releaseUrl"]
            and isinstance(release.get("target_commitish"), str)
            and HEX40.fullmatch(release["target_commitish"]),
            "Release publication/tag/source mismatch")
    result = {}
    ids = set()
    for a in release.get("assets", []):
        require(type(a) is dict and type(a.get("id")) is int and a["id"] > 0
                and a["id"] not in ids and type(a.get("size")) is int and a["size"] > 0
                and a.get("state") == "uploaded"
                and isinstance(a.get("digest"), str)
                and re.fullmatch(r"sha256:[a-f0-9]{64}", a["digest"]),
                "untrusted Release asset metadata")
        name = safe_component(a.get("name"))
        require(name.casefold() not in {s.casefold() for s in result},
                "duplicate/case-colliding Release asset")
        require(a.get("browser_download_url") ==
                "https://github.com/" + repo + "/releases/download/" +
                release["tag_name"] + "/" + name, "Release asset URL swapped")
        result[name] = a
        ids.add(a["id"])
    require(result and "SHA256SUMS.txt" in result, "missing Release checksum asset")
    for major, row in record["postgresql"].items():
        if row.get("available") is not True:
            continue
        require(row.get("asset") in result
                and result[row["asset"]]["digest"] == "sha256:" + row.get("sha256", ""),
                "Release ZIP digest differs from Catalog: PG" + major)
        for field in ("sbom", "vulnerabilityReport"):
            e = (row.get("evidence") or {}).get(field) or {}
            require(e.get("available") is True and e.get("asset") in result
                    and result[e["asset"]]["digest"] == "sha256:" + e.get("sha256", ""),
                    "Release evidence digest differs from Catalog: PG" + major)
    return result


def parse_sums(data):
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise Denied("SHA256SUMS non-ASCII") from exc
    require(bool(lines), "empty checksum file")
    sums = {}
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None and match[2] not in sums,
                "invalid/duplicate checksum")
        sums[match[2]] = match[1]
    return sums


def rehash_release(directory, assets, record):
    """Read ALL formal Release assets and original SHA256SUMS, without network."""
    require(directory.is_dir() and not directory.is_symlink()
            and sum(a["size"] for a in assets.values()) <= MAX_RELEASE,
            "release folder or size limit invalid")
    entries = list(directory.iterdir())
    require(len(entries) == len(assets) and {p.name for p in entries} == set(assets)
            and all(p.is_file() and not p.is_symlink() for p in entries),
            "missing/additional/linked Release files")
    hashes = {}
    for filename, a in assets.items():
        path = directory / filename
        require(path.stat().st_size == a["size"], "Release asset size mismatch")
        hashes[filename] = sha(path)
        require(a["digest"] == "sha256:" + hashes[filename],
                "GitHub asset digest differs from independently hashed bytes")
    sums = parse_sums((directory / "SHA256SUMS.txt").read_bytes())
    require(set(sums) == set(assets) - {"SHA256SUMS.txt"}
            and all(hashes[n] == d for n, d in sums.items()),
            "SHA256SUMS bytes disagree with downloaded assets")
    for major, row in record["postgresql"].items():
        if row.get("available") is not True:
            continue
        require(row.get("asset") in assets and hashes[row["asset"]] == row.get("sha256"),
                "Catalog ZIP SHA mismatch " + major)
        for field in ("sbom", "vulnerabilityReport"):
            e = (row.get("evidence") or {}).get(field) or {}
            require(e.get("available") is True and e.get("asset") in assets
                    and hashes[e["asset"]] == e.get("sha256"),
                    "Catalog SPDX/Grype SHA mismatch " + major)
    return hashes


def inspect_package(zip_path, spdx_path, grype_path, *, repository, major,
                    immutable_packaging_sha, source):
    """Never extract ZIP; verify all CRCs, PACKAGE-INFO and report formats."""
    try:
        with ZipFile(zip_path) as z:
            verify_archive_members(z)
            info = [v for v in z.infolist() if v.filename == "PACKAGE-INFO.json"]
            require(len(info) == 1 and info[0].file_size <= 262144,
                    "ambiguous/oversized PACKAGE-INFO")
            for member in z.infolist():
                if not member.is_dir():
                    with z.open(member) as fd:
                        while fd.read(1024 * 1024):
                            pass
            pkg = strict_json(z.read("PACKAGE-INFO.json").decode("utf-8-sig"))
        sbom = strict_json(spdx_path.read_bytes())
        grype = strict_json(grype_path.read_bytes())
    except (BadZipFile, OSError, ValueError, UnicodeError, RuntimeError) as exc:
        raise Denied("invalid ZIP/CRC/SBOM/Grype data") from exc
    require(sbom.get("spdxVersion") == "SPDX-2.3"
            and type(grype.get("matches")) is list, "invalid SPDX/Grype structure")
    run_id = check_source_package(pkg, repository, immutable_packaging_sha,
                                  major, source)
    workflow = pkg.get("workflowRun") or {}
    infra = pkg.get("buildInfrastructure") or {}
    require(type(workflow.get("attempt")) is int and workflow["attempt"] > 0
            and workflow.get("url") == "https://github.com/" + repository
                     + "/actions/runs/" + str(run_id)
            and infra.get("repository") == "pgextwin/build"
            and infra.get("workflow") == ".github/workflows/build-extension-attested.yml"
            and isinstance(infra.get("commit"), str)
            and HEX40.fullmatch(infra["commit"]),
            "unbound run_attempt or signer build SHA")
    return {"runId": run_id, "runAttempt": workflow["attempt"],
            "signerSha": infra["commit"], "sbom": sbom}


def signed_run(run, *, repo, repo_id, packaging_sha, run_id, attempt):
    require(run.get("id") == run_id and run.get("run_attempt") == attempt
            and (run.get("repository") or {}).get("id") == repo_id
            and (run.get("repository") or {}).get("full_name") == repo
            and run.get("head_sha") == packaging_sha
            and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == ".github/workflows/promote.yml"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and isinstance((run.get("actor") or {}).get("login"), str)
            and not run["actor"]["login"].endswith("[bot]"),
            "run identity/source/attempt/formal success mismatch")


def signed_certificate(results, *, predicate, name, digest, sbom, repository,
                       repository_id, packaging_sha, signer_sha, run_id, attempt):
    """Policy on genuine gh-verified result. Calling this alone is NOT verification."""
    require(type(results) is list and bool(results), "no verified Sigstore result")
    invocation = "https://github.com/" + repository + "/actions/runs/" + str(run_id) + "/attempts/" + str(attempt)
    signer = "https://github.com/pgextwin/build/.github/workflows/build-extension-attested.yml@" + signer_sha
    hits = 0
    for item in results:
        v = item.get("verificationResult") if type(item) is dict else None
        st = v.get("statement") if type(v) is dict else None
        if type(st) is not dict or st.get("predicateType") != predicate:
            continue
        subjects = st.get("subject")
        if not (type(subjects) is list and any(
            type(s) is dict and s.get("name") == name
            and (s.get("digest") or {}).get("sha256") == digest for s in subjects)):
            continue
        cert = (v.get("signature") or {}).get("certificate")
        require(type(cert) is dict and type(v.get("verifiedTimestamps")) is list
                and bool(v["verifiedTimestamps"]), "missing certified timestamp")
        require(cert.get("issuer") == ISSUER
                and cert.get("sourceRepositoryURI") == "https://github.com/" + repository
                and str(cert.get("sourceRepositoryIdentifier")) == str(repository_id)
                and cert.get("sourceRepositoryDigest") == packaging_sha
                and cert.get("sourceRepositoryRef") == "refs/heads/main"
                and cert.get("runInvocationURI") == invocation
                and cert.get("buildTrigger") == "workflow_dispatch"
                and cert.get("buildSignerURI") == signer
                and cert.get("subjectAlternativeName") == signer
                and cert.get("buildSignerDigest") == signer_sha
                and cert.get("githubWorkflowSHA") == packaging_sha
                and cert.get("githubWorkflowRef") == "refs/heads/main",
                "certified issuer/repo ID/workflow/source/attempt mismatch")
        pred = st.get("predicate")
        require(type(pred) is dict, "missing signed predicate")
        if predicate == SPDX:
            require(pred == sbom and pred.get("spdxVersion") == "SPDX-2.3",
                    "signed SBOM does not match Release bytes")
        else:
            require(((pred.get("runDetails") or {}).get("metadata") or {})
                    .get("invocationId") == invocation, "SLSA run attempt mismatch")
        hits += 1
    require(hits == 1, "absent/duplicate exact signer subject")


def verify_sigstore_offline(zip_path, sbom, *, repo, repo_id, packaging_sha,
                            signer_sha, run_id, attempt, root_path, root_sha,
                            bundles):
    """Only real gh attestation verify, local bundles and externally pinned root."""
    require(root_path.is_file() and not root_path.is_symlink()
            and isinstance(root_sha, str) and HEX64.fullmatch(root_sha)
            and sha(root_path) == root_sha, "unauthenticated/rotated trusted root")
    require(type(bundles) is dict and set(bundles) == set(PREDICATES),
            "SLSA and SPDX bundles both mandatory")
    proofs = {}
    for predicate in PREDICATES:
        bundle, expected_hash = bundles[predicate]
        require(bundle.is_file() and not bundle.is_symlink()
                and isinstance(expected_hash, str) and HEX64.fullmatch(expected_hash)
                and sha(bundle) == expected_hash,
                "missing or substituted Sigstore bundle")
        cmd = ("gh", "attestation", "verify", str(zip_path), "--repo", repo,
               "--bundle", str(bundle), "--custom-trusted-root", str(root_path),
               "--signer-workflow", SIGNER, "--signer-digest", signer_sha,
               "--source-ref", "refs/heads/main", "--source-digest", packaging_sha,
               "--cert-oidc-issuer", ISSUER, "--predicate-type", predicate,
               "--format", "json")
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=180,
                                  check=False, env={"GH_NO_UPDATE_NOTIFIER": "1",
                                                    "GH_PROMPT_DISABLED": "1"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Denied("gh Sigstore verifier unavailable") from exc
        require(proc.returncode == 0, "cryptographic Sigstore verification FAILED")
        result = strict_json(proc.stdout)
        signed_certificate(result, predicate=predicate, name=zip_path.name,
                           digest=sha(zip_path), sbom=sbom, repository=repo,
                           repository_id=repo_id, packaging_sha=packaging_sha,
                           signer_sha=signer_sha, run_id=run_id, attempt=attempt)
        proofs[predicate] = expected_hash
    return {"integrityVerified": True, "signatureVerified": True,
            "trustedRootSha256": root_sha, "bundleSha256": proofs,
            "publicationAuthorized": False}


def fleet_counts(records, decisions):
    """Dynamic fleet; unsigned, unsupported and missing rows cannot count as PASS."""
    expected = {(name, major) for name, record in records.items()
                for major, entry in record["postgresql"].items()
                if entry.get("available") is True}
    require(set(decisions).issubset(expected), "unknown or extra major decision")
    totals = {"expected": len(expected), "integrityVerified": 0,
              "signatureVerified": 0, "unverified": 0, "blocked": 0,
              "reasons": {}, "publicationAuthorized": False}
    for pair in sorted(expected):
        d = decisions.get(pair)
        if d is None:
            totals["unverified"] += 1
        elif d.get("integrityVerified") is True and d.get("signatureVerified") is True:
            totals["integrityVerified"] += 1
            totals["signatureVerified"] += 1
        elif d.get("integrityVerified") is True:
            totals["integrityVerified"] += 1
            totals["blocked"] += 1
            totals["reasons"]["/".join(pair)] = d.get("reason", "no genuine Sigstore proof")
        else:
            totals["blocked"] += 1
            totals["reasons"]["/".join(pair)] = d.get("reason", "verification failed")
    totals["complete"] = totals["signatureVerified"] == totals["expected"]
    return totals
