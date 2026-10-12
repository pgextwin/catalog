#!/usr/bin/env python3
"""Issue #75 Phase D: strictly read-only Catalog Release drift classification.

This offline preflight cannot validate signatures, propose a PR, dispatch,
publish or change Catalog data. Its sole purpose is to select whether an
independent signed-Release verifier would have work to do. Input JSON must
eventually be fetched from trusted, paginated GitHub GET endpoints.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re

from verified_release_record import ALLOWED, Denied, require

TAG = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def published_at(value):
    require(type(value) is str, "missing Release publication timestamp")
    try:
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Denied("invalid Release publication timestamp") from exc
    require(value.tzinfo is not None, "timestamp missing timezone")
    return value


def classify(record, releases, *, pending_tags=()):
    """Classify ONLY; never certify candidate assets or authorize an action.

    A full first page (<100 items) is required by this initial pilot; 100
    items requires a proper pagination reader rather than silently accepting
    an incomplete Release history. Pending tags must come from API-verified
    open Catalog proposals, never PR titles or bodies.
    """
    require(type(record) is dict and record.get("schemaVersion") == 2
            and record.get("name") in ALLOWED
            and record.get("repository") == "pgextwin/" + record["name"],
            "record is not one of the fourteen named repositories")
    current = record.get("latest")
    require(type(current) is dict and type(current.get("releaseTag")) is str
            and TAG.fullmatch(current["releaseTag"]) is not None,
            "Catalog current Release is missing or malformed")
    current_time = published_at(current.get("publishedAt"))
    require(type(releases) is list and 0 < len(releases) < 100,
            "missing or potentially unpaginated Release history")
    require(type(pending_tags) in (list, tuple, set, frozenset)
            and all(type(tag) is str and TAG.fullmatch(tag) for tag in pending_tags)
            and len(set(pending_tags)) == len(pending_tags),
            "ambiguous or untrusted pending proposal tags")
    stable = []
    seen = set()
    for release in releases:
        require(type(release) is dict, "invalid GitHub Release object")
        tag = release.get("tag_name")
        require(type(tag) is str and tag not in seen,
                "duplicate or missing GitHub Release tag")
        seen.add(tag)
        if release.get("draft") is True or release.get("prerelease") is True:
            continue
        require(release.get("draft") is False and release.get("prerelease") is False
                and TAG.fullmatch(tag) is not None
                and isinstance(release.get("target_commitish"), str)
                and SHA.fullmatch(release["target_commitish"]) is not None
                and isinstance(release.get("assets"), list)
                and len(release["assets"]) > 0,
                "malformed stable Release requires investigation")
        stable.append((published_at(release.get("published_at")), tag))
    require(stable and len({when for when, _tag in stable}) == len(stable),
            "ambiguous shared publication timestamps across Release tags")
    matching = [when for when, tag in stable if tag == current["releaseTag"]]
    require(len(matching) == 1 and matching[0] == current_time,
            "Catalog current Release is not independently confirmed by history")
    newest_time, newest_tag = max(stable)
    require(newest_time >= current_time, "attempted Catalog rollback")
    output = {
        "schemaVersion": 1, "repository": record["repository"],
        "catalogTag": current["releaseTag"],
        "candidateTag": newest_tag,
        "verifiedSignedRelease": False,
        "proposalAuthorized": False,
        "mutationsEnabled": False,
    }
    if newest_tag == current["releaseTag"]:
        output["status"] = "NO_CHANGE"
    elif newest_tag in pending_tags:
        output["status"] = "EXISTING_PROPOSAL"
    elif pending_tags:
        output["status"] = "BLOCKED_CONFLICT"
    else:
        output["status"] = "VERIFY_SIGNED_RELEASE_FIRST"
    return output


def main():
    parser = argparse.ArgumentParser(description="Offline read-only drift classifier")
    parser.add_argument("--record-json", type=Path, required=True)
    parser.add_argument("--releases-json", type=Path, required=True)
    parser.add_argument("--pending-tags-json", type=Path)
    args = parser.parse_args()
    try:
        record = json.loads(args.record_json.read_text(encoding="utf-8"))
        releases = json.loads(args.releases_json.read_text(encoding="utf-8"))
        pending = (json.loads(args.pending_tags_json.read_text(encoding="utf-8"))
                   if args.pending_tags_json else [])
        print(json.dumps(classify(record, releases, pending_tags=pending), sort_keys=True))
        return 0
    except (Denied, ValueError, TypeError, KeyError, OSError) as exc:
        print("CATALOG DRIFT DENIED (read only): " + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
