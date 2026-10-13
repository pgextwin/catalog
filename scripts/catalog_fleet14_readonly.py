#!/usr/bin/env python3
"""Issue #75: one-shot, protected-main 14-extension read-only metadata canary.

The existing wal2json 09:30 JST schedule remains untouched. This canary is
push/path-only and DOES NOT schedule 14 new watchers. No signed Release proof,
Release/tag, proposal, merge, dispatch, Secret, or publication capability.
"""
from __future__ import annotations

import json
import os
import re

from catalog_scheduled_readonly import GitHubReadOnly, audit
from verified_release_record import ALLOWED, Denied, require

NAMES = tuple(sorted(ALLOWED))
MAIN_REPO = "pgextwin/catalog"
SHA = re.compile(r"^[0-9a-f]{40}$")
PR_PATH = "pulls?state=open&base=main&per_page=100"
STATUS = frozenset({"NO_CHANGE", "VERIFY_SIGNED_RELEASE_FIRST",
                    "BLOCKED_OPEN_RECORD_PR"})


def _main_sha(api):
    branch = api.get(MAIN_REPO, "branches/main")
    require(type(branch) is dict and branch.get("protected") is True
            and type(branch.get("commit")) is dict
            and type(branch["commit"].get("sha")) is str
            and SHA.fullmatch(branch["commit"]["sha"]) is not None,
            "Catalog main is unprotected or cannot be verified")
    return branch["commit"]["sha"]


def _open_pr_snapshot(api):
    # One complete open PR page (GET reader denies Link next).
    prs = api.get(MAIN_REPO, PR_PATH)
    require(type(prs) is list and len(prs) < 100, "incomplete open PR inventory")
    identities = []
    for pr in prs:
        require(type(pr) is dict and type(pr.get("number")) is int
                and pr["number"] > 0 and pr.get("state") == "open"
                and type(pr.get("base")) is dict
                and pr["base"].get("ref") == "main"
                and type(pr.get("head")) is dict
                and type(pr["head"].get("sha")) is str
                and SHA.fullmatch(pr["head"]["sha"]) is not None,
                "malformed open PR identity")
        identities.append((pr["number"], pr["head"]["sha"]))
    require(len(set(identities)) == len(identities)
            and len({n for n, _ in identities}) == len(identities),
            "duplicate open PR identity")
    return tuple(sorted(identities))


def audit_fleet(api, *, expected_main_sha):
    """Two independent source snapshots PER extension, fenced on both sides.

    Not an atomic fleet-wide transaction. Detect main and open-PR races;
    each extension must have its own stable double-read Release and record.
    """
    require(type(expected_main_sha) is str
            and SHA.fullmatch(expected_main_sha) is not None,
            "trusted triggering Catalog commit missing")
    require(len(NAMES) == 14 and len(set(NAMES)) == 14
            and set(NAMES) == set(ALLOWED), "unexpected fleet allowlist")
    require(_main_sha(api) == expected_main_sha,
            "protected Catalog main does not match triggering SHA")
    first_prs = _open_pr_snapshot(api)
    results = []
    for extension in NAMES:
        checked = audit(api, extension)
        require(type(checked) is dict
                and checked.get("extension") == extension
                and checked.get("catalogMainSha") == expected_main_sha
                and checked.get("snapshotCount") == 2
                and checked.get("source") == "authenticated-github-readonly"
                and checked.get("status") in STATUS
                and checked.get("publishableReceipt") is False
                and checked.get("proposalAuthorized") is False
                and checked.get("mutationsEnabled") is False
                and checked.get("verifiedSignedRelease") is False,
                "fleet entry incomplete or could authorize publication")
        blockers = checked.get("openRecordProposalPrs")
        require(type(blockers) is list
                and len(set(blockers)) == len(blockers)
                and all(type(x) is int and x > 0 for x in blockers)
                and (checked["status"] == "BLOCKED_OPEN_RECORD_PR") == bool(blockers),
                "untrusted/duplicate open record PR proof")
        require(type(checked.get("catalogTag")) is str
                and type(checked.get("candidateTag")) is str,
                "fleet entry missing Release tag identities")
        results.append({
            "extension": extension,
            "status": checked["status"],
            "catalogTag": checked["catalogTag"],
            "candidateTag": checked["candidateTag"],
            "openRecordProposalPrs": blockers,
        })
    require(_main_sha(api) == expected_main_sha,
            "protected Catalog main advanced during 14-repository scan")
    require(_open_pr_snapshot(api) == first_prs,
            "open Catalog PR inventory changed during fleet scan")
    # A drift or open proposal is NOT 'NO_CHANGE' and never promotes an asset.
    is_same = all(x["status"] == "NO_CHANGE" for x in results)
    return {
        "status": "FLEET_METADATA_NO_CHANGE" if is_same
                  else "FLEET_REQUIRES_INDEPENDENT_RELEASE_REVIEW",
        "catalogMainSha": expected_main_sha,
        "fleetSize": len(NAMES),
        "snapshotCountPerExtension": 2,
        "extensions": results,
        "source": "authenticated-github-readonly",
        "fleetWideAtomicSnapshot": False,
        "verifiedSignedRelease": False,
        "proposalAuthorized": False,
        "mutationsEnabled": False,
        "publishableReceipt": False,
    }


def main():
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == MAIN_REPO
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GITHUB_EVENT_NAME") == "push",
                "only protected main push may run this one-off canary")
        proof = audit_fleet(
            GitHubReadOnly(os.environ.get("GITHUB_TOKEN", "")),
            expected_main_sha=os.environ.get("GITHUB_SHA", ""),
        )
        # Each result is checked against the 14-name allowlist and strict
        # metadata schema. Never output untrusted remote error text.
        print(json.dumps(proof, ensure_ascii=True, sort_keys=True))
        print("DRY_RUN_FLEET14_METADATA_ONLY; signedRelease=false; publishableReceipt=false")
        return 0
    except Exception:
        print("DENY: 14-extension read-only Catalog canary incomplete; "
              "publishableReceipt=false")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
