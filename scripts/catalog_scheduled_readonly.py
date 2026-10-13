#!/usr/bin/env python3
"""Issue #75: nonpublishing scheduled wal2json Catalog drift audit.

This is an authenticated, GitHub-GET-only two-snapshot metadata comparison.
It never verifies signed Release artifacts, writes Catalog records, creates
PRs, merges, dispatches or publishes. A successful NO_CHANGE report is not
a cryptographic supply-chain acceptance or an authorization for publication.
"""
from __future__ import annotations

import json
import os
import re

from catalog_drift_live_readonly import GitHubReadOnly, inspect
from verified_release_record import Denied, require

EXTENSION = "wal2json"
SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")
ALLOWED = frozenset({
    "NO_CHANGE", "VERIFY_SIGNED_RELEASE_FIRST", "BLOCKED_OPEN_RECORD_PR",
})


def audited_snapshot(api):
    result = inspect(api, EXTENSION)
    require(type(result) is dict
            and result.get("source") == "authenticated-github-readonly"
            and result.get("repository") == "pgextwin/wal2json"
            and result.get("status") in ALLOWED
            and result.get("gitHubCollectionsComplete") is True
            and result.get("candidateArtifactsAndAttestation") == "NOT_VERIFIED"
            and result.get("verifiedSignedRelease") is False
            and result.get("proposalAuthorized") is False
            and result.get("mutationsEnabled") is False,
            "drift result cannot authorize signed Release or mutation")
    require(type(result.get("catalogMainSha")) is str
            and SHA.fullmatch(result["catalogMainSha"]) is not None
            and type(result.get("catalogRecordBlobSha")) is str
            and SHA.fullmatch(result["catalogRecordBlobSha"]) is not None
            and type(result.get("publicReleaseCount")) is int
            and 0 < result["publicReleaseCount"] < 100
            and type(result.get("candidateTag")) is str
            and TAG.fullmatch(result["candidateTag"]) is not None
            and type(result.get("catalogTag")) is str
            and TAG.fullmatch(result["catalogTag"]) is not None,
            "incomplete Catalog identity proof")
    blockers = result.get("openRecordProposalPrs")
    require(type(blockers) is list and all(
        type(n) is int and n > 0 for n in blockers
    ) and len(set(blockers)) == len(blockers),
            "duplicate or unknown open Catalog proposal inventory")
    require((result["status"] == "BLOCKED_OPEN_RECORD_PR") == bool(blockers),
            "record conflict or duplicate-pr detection inconsistent")
    # Exactly these fields are used to detect TOCTOU, not self-asserted
    # "verifiedSignedRelease" or a candidate Release tag.
    return result


def audit(api):
    first = audited_snapshot(api)
    second = audited_snapshot(api)
    require(first == second, "GitHub Catalog/Release/open PR evidence raced")
    return {
        "status": first["status"],
        "extension": EXTENSION,
        "catalogTag": first["catalogTag"],
        "candidateTag": first["candidateTag"],
        "catalogMainSha": first["catalogMainSha"],
        "openRecordProposalPrs": first["openRecordProposalPrs"],
        "source": "authenticated-github-readonly",
        "snapshotCount": 2,
        "verifiedSignedRelease": False,
        "proposalAuthorized": False,
        "mutationsEnabled": False,
        "publishableReceipt": False,
    }


def main():
    try:
        require(
            os.environ.get("GITHUB_REPOSITORY") == "pgextwin/catalog"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in {"push", "schedule"},
            "non-main or unauthorized Catalog trigger")
        token = os.environ.get("GITHUB_TOKEN", "")
        result = audit(GitHubReadOnly(token))
        # Only allowlisted, schema-validated scalar status is emitted;
        # never log credentials, raw GitHub API responses or Release assets.
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print("DENY: Catalog read-only drift evidence unavailable or changed; "
              "publishableReceipt=false")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
