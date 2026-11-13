#!/usr/bin/env python3
"""Issue #112: deterministic *nonpublishing* multi-provider external ZIP intake.

The inputs are historical discovery metadata, never an authorization feed.
A plan is suitable for batching independent byte/runtime/rights investigations,
NOT for consumers, downloads, issuers, Sigstore, releases, or promotion.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("external/windows-candidates-v1.json",
          "external/windows-candidates-portalcorp-v1.json",
          "external/windows-candidates-pglogical-v1.json")
PROVIDERS = "external/discovery-providers-v1.json"
SCHEMA = "pgextwin-issue112-external-review-batches/v1"
SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
SAFE = re.compile(r"[A-Za-z0-9_.+-]+\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
# The original two providers are explicitly on P3 hold. A new intake must
# never silently bypass that decision, including older versions or PG majors.
HELD = frozenset(("laurenz/oracle_fdw", "andreiramani/pgvector_pgsql_windows"))
SUPPORTED = frozenset(("14", "15", "16", "17", "18"))


class Denied(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Denied("external batch plan DENY: " + reason)


def unique(pairs):
    d = {}
    for k, v in pairs:
        require(k not in d, "duplicate JSON key")
        d[k] = v
    return d


def read(root, rel):
    p = root / rel
    require(p.is_file() and not p.is_symlink() and p.stat().st_size < 8_000_000,
            "missing/oversized/linked immutable input " + rel)
    return json.loads(p.read_text("utf-8"), object_pairs_hook=unique)


def format_of(asset):
    if asset.endswith(".zip"):
        return "zip"
    if asset.endswith(".7z"):
        return "7z"
    if asset.endswith(".exe"):
        return "exe"
    return "unsupported"


def blocking_reasons(row, fmt, held):
    reasons = []
    if held:
        reasons.append("EXISTING_P3_HOLD")
    if row["pgMajor"] not in SUPPORTED:
        reasons.append("POSTGRESQL_EOL_OR_OUT_OF_SCOPE")
    if fmt != "zip":
        reasons.append("ARCHIVE_FORMAT_ADAPTER_UNVERIFIED")
    if row.get("historical") is True:
        reasons.append("HISTORICAL_EXACT_VERSION_OPT_IN_REQUIRED")
    if not row.get("originalSha256") or not row.get("originalBytes"):
        reasons.append("INDEPENDENT_ORIGINAL_BYTES_NOT_PINNED")
    if row.get("compatibilityVerified") is not True:
        reasons.append("WINDOWS_PG_RUNTIME_NOT_ACCEPTED")
    if row.get("dependenciesVerified") is not True:
        reasons.append("DEPENDENCIES_NOT_ACCEPTED")
    if row.get("rightsReviewed") is not True:
        reasons.append("LICENSE_NOTICE_NOT_ACCEPTED")
    if row.get("provenanceVerified") is not True:
        reasons.append("PROVIDER_PROVENANCE_NOT_ACCEPTED")
    # Even a fully inspected asset cannot be admitted by this function.
    reasons.append("INDEPENDENT_SIGNED_SOURCE_AUTHORIZATION_REQUIRED")
    return reasons


def build(root=ROOT, max_batch=12, pg_filter=None):
    root = Path(root)
    require(type(max_batch) is int and 1 <= max_batch <= 20, "invalid bounded batch size")
    require(pg_filter is None or pg_filter in SUPPORTED, "unsupported PG filter")
    allow = read(root, PROVIDERS)
    require(allow.get("schemaVersion") == "pgextwin-external-discovery-providers/v1"
            and allow.get("trust") == "READ_ONLY_METADATA_NEVER_AUTHORIZE"
            and allow.get("githubApiHost") == "api.github.com", "untrusted provider allowlist")
    providers = allow.get("providers")
    require(isinstance(providers, list) and 1 <= len(providers) <= 24,
            "unbounded source allowlist")
    known = {}
    for p in providers:
        require(type(p) is dict and set(p) == {
            "repo", "providerType", "extension", "assetPattern"}, "bad provider declaration")
        repo = p["repo"]
        require(type(repo) is str and REPO.fullmatch(repo) and repo.lower() not in known,
                "duplicate or invalid provider")
        known[repo.lower()] = p
    all_rows = []
    seen = set()
    for rel in INPUTS:
        doc = read(root, rel)
        require(doc.get("schemaVersion") == "pgextwin-windows-source-candidates/v1"
                and doc.get("trust") == "UNVERIFIED_METADATA_ONLY"
                and doc.get("publicationAuthorized") is False
                and doc.get("redistributionAuthorized") is False
                and type(doc.get("candidates")) is list, "candidate registry is not deny-only")
        for row in doc["candidates"]:
            require(type(row) is dict, "invalid asset record")
            repo = row.get("sourceRepo")
            require(type(repo) is str and repo.lower() in known,
                    "provider is absent from reviewed discovery allowlist")
            provider = known[repo.lower()]
            require(row.get("providerType") == provider["providerType"]
                    and row.get("extension") == provider["extension"]
                    and type(row.get("assetName")) is str
                    and SAFE.fullmatch(row["assetName"]) is not None,
                    "provider/extension/asset identity contradiction")
            require(type(row.get("releaseId")) is int and row["releaseId"] > 0
                    and type(row.get("assetId")) is int and row["assetId"] > 0,
                    "unsafe provider release/asset ID")
            ident = (repo.lower(), row["releaseId"], row["assetId"])
            require(ident not in seen, "duplicate provider release/asset across registries")
            seen.add(ident)
            require(row.get("downloadAuthorized") is False
                    and row.get("redistributionAuthorization") == "not-authorized",
                    "untrusted discovery record attempted download promotion")
            raw_sha = row.get("apiDigest")
            require(raw_sha is None or (type(raw_sha) is str and
                    raw_sha.startswith("sha256:") and SHA256.fullmatch(raw_sha)),
                    "invalid untrusted provider API digest")
            original_sha = row.get("originalSha256")
            require(original_sha is None or (type(original_sha) is str and
                    re.fullmatch(r"[0-9a-f]{64}", original_sha)),
                    "invalid independent original digest")
            require(type(row.get("pgMajor")) is str and
                    type(row.get("upstreamVersion")) is str and
                    type(row.get("releaseTag")) is str, "missing source version/PG")
            if pg_filter is not None and row["pgMajor"] != pg_filter:
                continue
            fmt = format_of(row["assetName"])
            blockers = blocking_reasons(row, fmt, repo.lower() in HELD)
            all_rows.append({
                "extension": row["extension"], "pgMajor": row["pgMajor"],
                "version": row["upstreamVersion"], "provider": repo,
                "providerType": row["providerType"],
                "releaseId": row["releaseId"], "assetId": row["assetId"],
                "releaseTag": row["releaseTag"], "assetName": row["assetName"],
                "format": fmt, "originalBytes": row.get("originalBytes"),
                "originalSha256": original_sha,
                "apiDigestUntrusted": raw_sha, "blockers": blockers,
                "downloadAuthorized": False, "mirrorAuthorized": False,
            })
    # Group sources into bounded, independent validation batches; a single
    # held or unsupported item cannot block unrelated providers / PG versions.
    groups = defaultdict(list)
    for item in all_rows:
        groups[(item["provider"], item["pgMajor"], item["format"])].append(item)
    batches = []
    for (repo, major, fmt), records in sorted(groups.items()):
        records.sort(key=lambda r: (r["version"], r["releaseId"], r["assetId"]))
        for i in range(0, len(records), max_batch):
            cohort = records[i:i + max_batch]
            batches.append({
                "batchId": f"batch-{len(batches)+1:03d}",
                "provider": repo, "pgMajor": major, "format": fmt,
                "records": cohort,
                "reviewOnly": True, "downloadAuthorized": False,
                "mirrorAuthorized": False, "publisherInvocationAuthorized": False,
            })
    return {
        "schemaVersion": SCHEMA,
        "trust": "UNVERIFIED_METADATA_ONLY",
        "source": list(INPUTS), "pgSelection": pg_filter or "all",
        "totalCandidateAssets": len(all_rows),
        "heldAssetCount": sum(r["provider"].lower() in HELD for r in all_rows),
        "reviewBatchCount": len(batches),
        "providerCount": len({r["provider"].lower() for r in all_rows}),
        "admittedAssets": 0, "downloadAuthorized": False,
        "mirrorAuthorized": False, "redistributionAuthorized": False,
        "publisherInvocationAuthorized": False,
        "batches": batches,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalog", type=Path, default=ROOT)
    p.add_argument("--pg", choices=sorted(SUPPORTED))
    p.add_argument("--max-batch", type=int, default=12)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    report = build(args.catalog, args.max_batch, args.pg)
    require(not args.output.exists() and not args.output.is_symlink(),
            "plan output must be create-only")
    args.output.write_text(json.dumps(report, sort_keys=True, ensure_ascii=False,
                                       indent=2) + "\n", encoding="utf-8")
    print(f"EXTERNAL_REVIEW_BATCHES={report['reviewBatchCount']} "
          f"CANDIDATES={report['totalCandidateAssets']} "
          f"HELD={report['heldAssetCount']} ADMITTED=0 "
          "DOWNLOAD_DENY MIRROR_DENY PUBLISH_DENY")


if __name__ == "__main__":
    main()
